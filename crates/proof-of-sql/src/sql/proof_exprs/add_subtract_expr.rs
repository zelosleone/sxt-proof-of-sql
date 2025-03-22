use super::{add_subtract_columns, scale_and_add_subtract_eval, DynProofExpr, ProofExpr};
use crate::{
    base::{
        database::{try_add_subtract_column_types, Column, ColumnRef, ColumnType, Table},
        map::{IndexMap, IndexSet},
        proof::ProofError,
        scalar::Scalar,
    },
    sql::proof::{FinalRoundBuilder, VerificationBuilder},
    utils::log,
};
use alloc::boxed::Box;
use bumpalo::Bump;
use serde::{Deserialize, Serialize};

/// Provable numerical `+` / `-` expression
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AddSubtractExpr {
    lhs: Box<DynProofExpr>,
    rhs: Box<DynProofExpr>,
    is_subtract: bool,
}

impl AddSubtractExpr {
    /// Create numerical `+` / `-` expression
    pub fn new(lhs: Box<DynProofExpr>, rhs: Box<DynProofExpr>, is_subtract: bool) -> Self {
        Self {
            lhs,
            rhs,
            is_subtract,
        }
    }
}

impl ProofExpr for AddSubtractExpr {
    fn data_type(&self) -> ColumnType {
        try_add_subtract_column_types(self.lhs.data_type(), self.rhs.data_type())
            .expect("Failed to add/subtract column types")
    }

    fn result_evaluate<'a, S: Scalar>(
        &self,
        alloc: &'a Bump,
        table: &Table<'a, S>,
    ) -> Column<'a, S> {
        let lhs_column: Column<'a, S> = self.lhs.result_evaluate(alloc, table);
        let rhs_column: Column<'a, S> = self.rhs.result_evaluate(alloc, table);
        Column::Scalar(add_subtract_columns(
            lhs_column,
            rhs_column,
            self.lhs.data_type().scale().unwrap_or(0),
            self.rhs.data_type().scale().unwrap_or(0),
            alloc,
            self.is_subtract,
        ))
    }

    #[tracing::instrument(
        name = "proofs.sql.ast.add_subtract_expr.prover_evaluate",
        level = "info",
        skip_all
    )]
    fn prover_evaluate<'a, S: Scalar>(
        &self,
        builder: &mut FinalRoundBuilder<'a, S>,
        alloc: &'a Bump,
        table: &Table<'a, S>,
    ) -> Column<'a, S> {
        log::log_memory_usage("Start");

        let lhs_column: Column<'a, S> = self.lhs.prover_evaluate(builder, alloc, table);
        let rhs_column: Column<'a, S> = self.rhs.prover_evaluate(builder, alloc, table);
        let res = Column::Scalar(add_subtract_columns(
            lhs_column,
            rhs_column,
            self.lhs.data_type().scale().unwrap_or(0),
            self.rhs.data_type().scale().unwrap_or(0),
            alloc,
            self.is_subtract,
        ));

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

        // For arithmetic operations, if either operand is NULL, the result is NULL
        // Combine presence information from both operands
        let presence = match (lhs_presence, rhs_presence) {
            (Some(lhs_p), Some(rhs_p)) => Some(lhs_p * rhs_p), // Both present = present
            (Some(lhs_p), None) => Some(lhs_p),                // Only LHS nullable
            (None, Some(rhs_p)) => Some(rhs_p),                // Only RHS nullable
            (None, None) => None,                              // Neither nullable
        };

        let res_value =
            scale_and_add_subtract_eval(lhs_value, rhs_value, lhs_scale, rhs_scale, self.is_subtract);
        Ok((res_value, presence))
    }

    fn get_column_references(&self, columns: &mut IndexSet<ColumnRef>) {
        self.lhs.get_column_references(columns);
        self.rhs.get_column_references(columns);
    }
}
