use crate::base::scalar::Scalar;
use alloc::vec::Vec;

/// The result of evaluating a table
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct TableEvaluation<S: Scalar> {
    /// Evaluation of each column in the table
    column_evals: Vec<S>,
    /// Optional presence evaluation for each column in the table
    /// If a column is not nullable, the corresponding presence evaluation is None
    presence_evals: Vec<Option<S>>,
    /// Evaluation of an all-one column with the same length as the table
    chi_eval: S,
}

impl<S: Scalar> TableEvaluation<S> {
    /// Creates a new [`TableEvaluation`] without presence information.
    #[must_use]
    pub fn new(column_evals: Vec<S>, chi_eval: S) -> Self {
        Self {
            column_evals: column_evals.clone(),
            presence_evals: vec![None; column_evals.len()],
            chi_eval,
        }
    }

    /// Creates a new [`TableEvaluation`] with presence information.
    #[must_use]
    pub fn with_presence(column_evals: Vec<S>, presence_evals: Vec<Option<S>>, chi_eval: S) -> Self {
        assert_eq!(column_evals.len(), presence_evals.len(), "Column and presence evaluations must have the same length");
        Self {
            column_evals,
            presence_evals,
            chi_eval,
        }
    }

    /// Returns the evaluation of each column in the table.
    #[must_use]
    pub fn column_evals(&self) -> &[S] {
        &self.column_evals
    }

    /// Returns the presence evaluation for each column in the table.
    #[must_use]
    pub fn presence_evals(&self) -> &[Option<S>] {
        &self.presence_evals
    }

    /// Returns the evaluation of an all-one column with the same length as the table.
    #[must_use]
    pub fn chi_eval(&self) -> S {
        self.chi_eval
    }
}
