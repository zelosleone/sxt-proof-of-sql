use super::{scale_and_add_subtract_eval, scale_and_subtract, DynProofExpr, ProofExpr};
use crate::{
    base::{
        database::{Column, ColumnRef, ColumnType, Table},
        map::{IndexMap, IndexSet},
        proof::ProofError,
        scalar::Scalar,
    },
    sql::{
        proof::{FinalRoundBuilder, VerificationBuilder},
        proof_gadgets::{prover_evaluate_sign, result_evaluate_sign, verifier_evaluate_sign},
    },
    utils::log,
};
use alloc::boxed::Box;
use bumpalo::Bump;
use serde::{Deserialize, Serialize};

/// Provable AST expression for an inequality expression
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InequalityExpr {
    lhs: Box<DynProofExpr>,
    rhs: Box<DynProofExpr>,
    is_lt: bool,
}

impl InequalityExpr {
    /// Create a new less than or equal
    pub fn new(lhs: Box<DynProofExpr>, rhs: Box<DynProofExpr>, is_lt: bool) -> Self {
        Self { lhs, rhs, is_lt }
    }
}

impl ProofExpr for InequalityExpr {
    fn data_type(&self) -> ColumnType {
        ColumnType::Boolean
    }

    #[tracing::instrument(name = "InequalityExpr::result_evaluate", level = "debug", skip_all)]
    fn result_evaluate<'a, S: Scalar>(
        &self,
        alloc: &'a Bump,
        table: &Table<'a, S>,
    ) -> Column<'a, S> {
        log::log_memory_usage("Start");

        let lhs_column = self.lhs.result_evaluate(alloc, table);
        let rhs_column = self.rhs.result_evaluate(alloc, table);
        let lhs_scale = self.lhs.data_type().scale().unwrap_or(0);
        let rhs_scale = self.rhs.data_type().scale().unwrap_or(0);
        let table_length = table.num_rows();
        let diff = if self.is_lt {
            scale_and_subtract(alloc, lhs_column, rhs_column, lhs_scale, rhs_scale, false)
                .expect("Failed to scale and subtract")
        } else {
            scale_and_subtract(alloc, rhs_column, lhs_column, rhs_scale, lhs_scale, false)
                .expect("Failed to scale and subtract")
        };

        // (sign(diff) == -1)
        let res = Column::Boolean(result_evaluate_sign(table_length, alloc, diff));

        log::log_memory_usage("End");

        res
    }

    #[tracing::instrument(name = "InequalityExpr::prover_evaluate", level = "debug", skip_all)]
    fn prover_evaluate<'a, S: Scalar>(
        &self,
        builder: &mut FinalRoundBuilder<'a, S>,
        alloc: &'a Bump,
        table: &Table<'a, S>,
    ) -> Column<'a, S> {
        log::log_memory_usage("Start");

        let lhs_column = self.lhs.prover_evaluate(builder, alloc, table);
        let rhs_column = self.rhs.prover_evaluate(builder, alloc, table);
        let lhs_scale = self.lhs.data_type().scale().unwrap_or(0);
        let rhs_scale = self.rhs.data_type().scale().unwrap_or(0);
        let diff = if self.is_lt {
            scale_and_subtract(alloc, lhs_column, rhs_column, lhs_scale, rhs_scale, false)
                .expect("Failed to scale and subtract")
        } else {
            scale_and_subtract(alloc, rhs_column, lhs_column, rhs_scale, lhs_scale, false)
                .expect("Failed to scale and subtract")
        };

        // (sign(diff) == -1)
        let res = Column::Boolean(prover_evaluate_sign(builder, alloc, diff));

        log::log_memory_usage("End");

        res
    }

    fn verifier_evaluate<S: Scalar>(
        &self,
        builder: &mut impl VerificationBuilder<S>,
        accessor: &IndexMap<ColumnRef, S>,
        chi_eval: S,
    ) -> Result<(S, Option<S>), ProofError> {
        let (lhs_value, lhs_presence) = self.lhs.verifier_evaluate(builder, accessor, chi_eval)?;
        let (rhs_value, rhs_presence) = self.rhs.verifier_evaluate(builder, accessor, chi_eval)?;
        let lhs_scale = self.lhs.data_type().scale().unwrap_or(0);
        let rhs_scale = self.rhs.data_type().scale().unwrap_or(0);

        // For comparison operations, if either operand is NULL, the result is NULL
        // Combine presence information from both operands
        let presence = match (lhs_presence, rhs_presence) {
            (Some(lhs_p), Some(rhs_p)) => Some(lhs_p * rhs_p), // Both present = present
            (Some(lhs_p), None) => Some(lhs_p),                // Only LHS nullable
            (None, Some(rhs_p)) => Some(rhs_p),                // Only RHS nullable
            (None, None) => None,                              // Neither nullable
        };

        let diff_value = if self.is_lt {
            scale_and_add_subtract_eval(lhs_value, rhs_value, lhs_scale, rhs_scale, true)
        } else {
            scale_and_add_subtract_eval(rhs_value, lhs_value, rhs_scale, lhs_scale, true)
        };

        // sign(diff) == -1
        let sign_value = verifier_evaluate_sign(builder, diff_value, chi_eval, None)?;

        Ok((sign_value, presence))
    }

    fn get_column_references(&self, columns: &mut IndexSet<ColumnRef>) {
        self.lhs.get_column_references(columns);
        self.rhs.get_column_references(columns);
    }
}
