use super::ProofExpr;
use crate::{
    base::{
        database::{Column, ColumnField, ColumnRef, ColumnType, NullableColumn, Table},
        map::{IndexMap, IndexSet},
        proof::ProofError,
        scalar::Scalar,
    },
    sql::proof::{FinalRoundBuilder, VerificationBuilder},
};
use bumpalo::Bump;
use serde::{Deserialize, Serialize};
use sqlparser::ast::Ident;
/// Provable expression for a column
///
/// Note: this is currently limited to named column expressions.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct ColumnExpr {
    pub(crate) column_ref: ColumnRef,
}

impl ColumnExpr {
    /// Create a new column expression
    #[must_use]
    pub fn new(column_ref: ColumnRef) -> Self {
        Self { column_ref }
    }

    /// Return the column referenced by this [`ColumnExpr`]
    #[must_use]
    pub fn get_column_reference(&self) -> ColumnRef {
        self.column_ref.clone()
    }

    /// Wrap the column output name and its type within the [`ColumnField`]
    #[must_use]
    pub fn get_column_field(&self) -> ColumnField {
        ColumnField::new(self.column_ref.column_id(), *self.column_ref.column_type())
    }

    /// Get the column identifier
    #[must_use]
    pub fn column_id(&self) -> Ident {
        self.column_ref.column_id()
    }

    /// Get the column
    /// # Panics
    ///
    /// Will panic if the column is not found. Shouldn't happen in practice since
    /// code in `sql/parse` should have already checked that the column exists.
    #[must_use]
    pub fn fetch_column<'a, S: Scalar>(&self, table: &Table<'a, S>) -> Column<'a, S> {
        *table
            .inner_table()
            .get(&self.column_ref.column_id())
            .expect("Column not found")
    }

    /// Get the column as a NullableColumn
    /// # Panics
    ///
    /// Will panic if the column is not found. Shouldn't happen in practice since
    /// code in `sql/parse` should have already checked that the column exists.
    #[must_use]
    pub fn fetch_nullable_column<'a, S: Scalar>(&self, table: &Table<'a, S>) -> NullableColumn<'a, S> {
        let column = self.fetch_column(table);
        let presence = table.presence_map().get(&self.column_ref.column_id()).copied();
        NullableColumn::with_presence(column, presence).expect("Presence length mismatch")
    }
}

impl ProofExpr for ColumnExpr {
    /// Get the data type of the expression
    fn data_type(&self) -> ColumnType {
        *self.get_column_reference().column_type()
    }

    /// Evaluate the column expression and
    /// add the result to the [`FirstRoundBuilder`](crate::sql::proof::FirstRoundBuilder)
    fn result_evaluate<'a, S: Scalar>(
        &self,
        _alloc: &'a Bump,
        table: &Table<'a, S>,
    ) -> Column<'a, S> {
        self.fetch_column(table)
    }

    /// Given the selected rows (as a slice of booleans), evaluate the column expression and
    /// add the components needed to prove the result
    fn prover_evaluate<'a, S: Scalar>(
        &self,
        _builder: &mut FinalRoundBuilder<'a, S>,
        _alloc: &'a Bump,
        table: &Table<'a, S>,
    ) -> Column<'a, S> {
        self.fetch_column(table)
    }

    /// Evaluate the column expression at the sumcheck's random point,
    /// add components needed to verify this column expression
    fn verifier_evaluate<S: Scalar>(
        &self,
        _builder: &mut impl VerificationBuilder<S>,
        accessor: &IndexMap<ColumnRef, S>,
        _chi_eval: S,
    ) -> Result<(S, Option<S>), ProofError> {
        let value = *accessor
            .get(&self.column_ref)
            .ok_or(ProofError::VerificationError {
                error: "Column Not Found",
            })?;

        // For presence, we need to check if this column is nullable
        // If it's nullable, we should have a presence evaluation in the accessor
        // We'll use a convention where nullable columns have a presence entry with a key
        // that has the same column_ref but with a "_presence" suffix
        let mut presence_column_ref = self.column_ref.clone();
        let mut presence_id = presence_column_ref.column_id().to_string();
        presence_id.push_str("_presence");
        presence_column_ref = ColumnRef::new(
            presence_column_ref.table_ref(),
            Ident::new(&presence_id),
            ColumnType::Boolean
        );

        let presence = accessor.get(&presence_column_ref).copied();

        Ok((value, presence))
    }

    /// Insert in the [`IndexSet`] `columns` all the column
    /// references in the `BoolExpr` or forwards the call to some
    /// subsequent `bool_expr`
    fn get_column_references(&self, columns: &mut IndexSet<ColumnRef>) {
        columns.insert(self.column_ref.clone());
    }
}
