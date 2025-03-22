use super::{DynProofExpr, ProofExpr};
use crate::{
    base::{
        database::{Column, ColumnRef, ColumnType, NullableColumn, Table},
        map::{IndexMap, IndexSet},
        proof::ProofError,
        scalar::Scalar,
    },
    sql::proof::{FinalRoundBuilder, SumcheckSubpolynomialType, VerificationBuilder},
    utils::log,
};
use alloc::{boxed::Box, vec};
use bumpalo::Bump;
use core::any;
use serde::{Deserialize, Serialize};

/// Provable IS TRUE expression, evaluates to TRUE if the expression is both not NULL and TRUE
/// This is particularly useful for WHERE clauses in SQL that require boolean expressions to be TRUE
/// (not NULL and not FALSE)
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IsTrueExpr {
    expr: Box<DynProofExpr>,
    pub(crate) malicious: bool,
}

impl IsTrueExpr {
    /// Create a new IS TRUE expression
    ///
    /// # Panics
    /// Panics if the provided expression is not a boolean expression
    pub fn new(expr: Box<DynProofExpr>) -> Self {
        assert!(
            expr.data_type() == ColumnType::Boolean,
            "IsTrueExpr can only be applied to boolean expressions, but got expression of type: {}",
            expr.data_type()
        );
        Self {
            expr,
            malicious: false,
        }
    }

    pub fn try_new(expr: Box<DynProofExpr>) -> Result<Self, ProofError> {
        if expr.data_type() != ColumnType::Boolean {
            return Err(ProofError::UnsupportedQueryPlan {
                error: "IsTrueExpr can only be applied to boolean expressions",
            });
        }
        Ok(Self {
            expr,
            malicious: false,
        })
    }

    pub fn is_inner_expr_or(&self) -> bool {
        let type_name = any::type_name_of_val(&*self.expr);
        type_name.contains("::Or")
    }
}

impl ProofExpr for IsTrueExpr {
    fn data_type(&self) -> ColumnType {
        ColumnType::Boolean
    }

    #[tracing::instrument(name = "IsTrueExpr::result_evaluate", level = "debug", skip_all)]
    fn result_evaluate<'a, S: Scalar>(
        &self,
        alloc: &'a Bump,
        table: &Table<'a, S>,
    ) -> Column<'a, S> {
        // Delegate to result_evaluate_nullable and return just the values
        self.result_evaluate_nullable(alloc, table).values
    }

    #[tracing::instrument(name = "IsTrueExpr::result_evaluate_nullable", level = "debug", skip_all)]
    fn result_evaluate_nullable<'a, S: Scalar>(
        &self,
        alloc: &'a Bump,
        table: &Table<'a, S>,
    ) -> NullableColumn<'a, S> {
        log::log_memory_usage("Start");

        let inner_nullable = self.expr.result_evaluate_nullable(alloc, table);
        let inner_values = inner_nullable.values
            .as_boolean()
            .expect("Expression is not boolean");

        if self.malicious {
            let result_slice = alloc.alloc_slice_fill_copy(table.num_rows(), true);
            let res = NullableColumn::new(Column::Boolean(result_slice));
            log::log_memory_usage("End");
            return res;
        }

        // Get presence information from the inner expression
        // If inner_nullable.presence is None, all values are present
        let inner_presence = inner_nullable.presence.unwrap_or_else(|| {
            alloc.alloc_slice_fill_copy(table.num_rows(), true)
        });

        // The result is true only if the inner value is true AND it's present (not null)
        // For SQL WHERE clauses, NULL values are treated as FALSE
        let result_slice = alloc
            .alloc_slice_fill_with(inner_values.len(), |i| inner_values[i] && inner_presence[i]);

        // IsTrueExpr always returns a non-nullable result (all values are present)
        // This is because SQL WHERE clauses treat NULL as FALSE, so the result is always a definite TRUE or FALSE
        let res = NullableColumn::new(Column::Boolean(result_slice));
        log::log_memory_usage("End");
        res
    }

    #[tracing::instrument(name = "IsTrueExpr::prover_evaluate", level = "debug", skip_all)]
    fn prover_evaluate<'a, S: Scalar>(
        &self,
        builder: &mut FinalRoundBuilder<'a, S>,
        alloc: &'a Bump,
        table: &Table<'a, S>,
    ) -> Column<'a, S> {
        // Delegate to prover_evaluate_nullable and return just the values
        self.prover_evaluate_nullable(builder, alloc, table).values
    }

    #[tracing::instrument(name = "IsTrueExpr::prover_evaluate_nullable", level = "debug", skip_all)]
    fn prover_evaluate_nullable<'a, S: Scalar>(
        &self,
        builder: &mut FinalRoundBuilder<'a, S>,
        alloc: &'a Bump,
        table: &Table<'a, S>,
    ) -> NullableColumn<'a, S> {
        log::log_memory_usage("Start");

        let inner_nullable = self.expr.prover_evaluate_nullable(builder, alloc, table);
        let inner_values = inner_nullable.values
            .as_boolean()
            .expect("Expression is not boolean");
        let n = table.num_rows();

        if self.malicious {
            let result_slice = alloc.alloc_slice_fill_copy(n, true);
            builder.produce_intermediate_mle(Column::Boolean(result_slice));
            builder.produce_sumcheck_subpolynomial(
                SumcheckSubpolynomialType::Identity,
                vec![(
                    S::one(),
                    vec![Box::new(alloc.alloc_slice_fill_copy(n, false) as &[_])],
                )],
            );

            let res = NullableColumn::new(Column::Boolean(result_slice));
            log::log_memory_usage("End");
            return res;
        }

        // Get presence information from the inner expression
        // If inner_nullable.presence is None, all values are present
        let presence_slice = inner_nullable.presence.unwrap_or_else(|| {
            alloc.alloc_slice_fill_copy(n, true)
        });

        builder.produce_intermediate_mle(presence_slice);
        builder.produce_intermediate_mle(inner_values);

        // The result is true only if the inner value is true AND it's present (not null)
        // For SQL WHERE clauses, NULL values are treated as FALSE
        let is_true_result: &[bool] =
            alloc.alloc_slice_fill_with(n, |i| inner_values[i] && presence_slice[i]);

        builder.produce_intermediate_mle(is_true_result);

        // Verify the constraint: is_true = inner_value AND presence
        // This is equivalent to is_true = inner_value * presence for boolean values
        builder.produce_sumcheck_subpolynomial(
            SumcheckSubpolynomialType::Identity,
            vec![
                (S::one(), vec![Box::new(is_true_result)]),
                (
                    -S::one(),
                    vec![Box::new(presence_slice), Box::new(inner_values)],
                ),
            ],
        );

        // IsTrueExpr always returns a non-nullable result (all values are present)
        let res = NullableColumn::new(Column::Boolean(is_true_result));
        log::log_memory_usage("End");
        res
    }

    fn verifier_evaluate<S: Scalar>(
        &self,
        builder: &mut impl VerificationBuilder<S>,
        accessor: &IndexMap<ColumnRef, S>,
        chi_eval: S,
    ) -> Result<(S, Option<S>), ProofError> {
        // Get the inner expression's value and presence evaluations
        let (inner_value_eval, inner_presence_eval) = self.expr.verifier_evaluate(builder, accessor, chi_eval)?;

        // If inner_presence_eval is None, use chi_eval (all values are present)
        let presence_eval = inner_presence_eval.unwrap_or_else(|| chi_eval);

        // Consume the presence evaluation from the builder
        let builder_presence_eval = builder.try_consume_final_round_mle_evaluation()?;

        // Verify that the presence evaluation matches what we expect
        if builder_presence_eval != presence_eval {
            return Err(ProofError::VerificationError {
                error: "Presence evaluation mismatch",
            });
        }

        // Consume the inner value evaluation from the builder
        let builder_inner_value_eval = builder.try_consume_final_round_mle_evaluation()?;

        // Verify that the inner value evaluation matches what we expect
        if builder_inner_value_eval != inner_value_eval {
            return Err(ProofError::VerificationError {
                error: "Inner value evaluation mismatch",
            });
        }

        // Consume the is_true evaluation from the builder
        let is_true_eval = builder.try_consume_final_round_mle_evaluation()?;

        // Verify the constraint: is_true = inner_value AND presence
        // For boolean values, logical AND is equivalent to multiplication
        // is_true = inner_value * presence
        builder.try_produce_sumcheck_subpolynomial_evaluation(
            SumcheckSubpolynomialType::Identity,
            is_true_eval - (inner_value_eval * presence_eval),
            2,
        )?;

        // IsTrueExpr always returns a non-nullable result
        Ok((is_true_eval, None))
    }

    fn get_column_references(&self, columns: &mut IndexSet<ColumnRef>) {
        self.expr.get_column_references(columns);
    }
}
