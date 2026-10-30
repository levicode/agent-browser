//! Same-operation proof for the ordinary, singleton ReadFields transaction.
//! Registry/attachment fences are owned by dispatch; no receipt is reusable by
//! another operation, client, ledger, frame, or callback.
use super::*;
use std::sync::Arc;

pub(crate) fn eligible(
    options: &QueryOptions,
    fields: &[ReadField],
    lease: &OperationLease,
) -> Result<bool, ObservationError> {
    validate_read_fields(fields)?;
    validate_expression(&options.expression, 0)?;
    Ok(!lease.is_callback
        && options.secure_field_selector == default_secure_selector()
        && fresh_query::eligible(&options.expression, fields))
}

/// None is a valid non-singleton topology, not a failed integrity check.
pub(crate) fn root_frame(
    tree: &Value,
    session: &str,
) -> Result<Option<ObservationFrame>, ObservationError> {
    let tree = tree
        .get("frameTree")
        .ok_or(ObservationError::BackendFailure)?;
    let frame = &tree["frame"];
    let id = frame["id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or(ObservationError::BackendFailure)?;
    let loader = frame["loaderId"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or(ObservationError::BackendFailure)?;
    if let Some(children) = tree.get("childFrames") {
        if !children
            .as_array()
            .ok_or(ObservationError::BackendFailure)?
            .is_empty()
        {
            return Ok(None);
        }
    }
    if let Some(parent) = frame.get("parentId") {
        parent
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or(ObservationError::BackendFailure)?;
        return Ok(None);
    }
    let url = frame["url"]
        .as_str()
        .ok_or(ObservationError::BackendFailure)?;
    Ok(Some(ObservationFrame {
        parent_frame_id: None,
        owner_backend_id: None,
        url: url.into(),
        binding: ExactBinding {
            page_session: session.into(),
            session: session.into(),
            frame: id.into(),
            loader: loader.into(),
            actionable: false,
        },
        offset_x: 0.0,
        offset_y: 0.0,
        frame_path: Vec::new(),
    }))
}

pub(crate) enum Sample {
    NotEligible,
    RequiresAx,
    Values(Vec<Value>),
}

pub(crate) struct RootRealm<'a> {
    client: &'a CdpClient,
    lease: &'a OperationLease,
    ledger: Arc<client_debt::OwnerDebtLedger>,
    frame: ObservationFrame,
    context: i64,
}
impl<'a> RootRealm<'a> {
    pub(crate) async fn acquire(
        client: &'a CdpClient,
        frame: &ObservationFrame,
        lease: &'a OperationLease,
    ) -> Result<Self, ObservationError> {
        check(lease)?;
        let ledger = client
            .debt_ledger()
            .ok_or(ObservationError::BackendFailure)?;
        if ledger
            .check_admission(client_debt::AdmissionClass::Reference)
            .is_err()
            || lease.is_callback
        {
            return Err(ObservationError::BackendFailure);
        }
        let world = command(
            client,
            &frame.binding.session,
            "Page.createIsolatedWorld",
            json!({"frameId":frame.binding.frame,"worldName":"agent-browser-native-observation"}),
            lease,
        )
        .await
        .map_err(|e| settled_stop(e, lease))?;
        let context = world["executionContextId"]
            .as_i64()
            .filter(|id| *id > 0)
            .ok_or(ObservationError::BackendFailure)?;
        let tree = command(
            client,
            &frame.binding.session,
            "Page.getFrameTree",
            json!({}),
            lease,
        )
        .await?;
        let current =
            root_frame(&tree, &frame.binding.session)?.ok_or(ObservationError::StaleReference)?;
        if current.binding != frame.binding || current.url != frame.url {
            return Err(ObservationError::StaleReference);
        }
        let receipt = Self {
            client,
            lease,
            ledger,
            frame: frame.clone(),
            context,
        };
        receipt.check(client, frame, lease)?;
        Ok(receipt)
    }
    pub(super) fn check(
        &self,
        client: &CdpClient,
        frame: &ObservationFrame,
        lease: &OperationLease,
    ) -> Result<(), ObservationError> {
        check(lease)?;
        // Borrow the original lease (including its cancellation channel and
        // deadline), not a sequence-number approximation of operation identity.
        if !std::ptr::eq(self.client, client)
            || !std::ptr::eq(self.lease, lease)
            || self.frame.binding != frame.binding
            || self.frame.url != frame.url
            || !client
                .debt_ledger()
                .is_some_and(|ledger| Arc::ptr_eq(&ledger, &self.ledger))
            || self
                .ledger
                .check_admission(client_debt::AdmissionClass::Reference)
                .is_err()
        {
            return Err(ObservationError::BackendFailure);
        }
        Ok(())
    }
    pub(super) fn context(
        &self,
        client: &CdpClient,
        frame: &ObservationFrame,
        lease: &OperationLease,
    ) -> Result<i64, ObservationError> {
        self.check(client, frame, lease)?;
        Ok(self.context)
    }
    pub(crate) async fn fields(
        &self,
        options: &QueryOptions,
        fields: &[ReadField],
        witness: Option<&query_diagnostic::QueryReadWitness>,
    ) -> Result<Sample, ObservationError> {
        let local = query_diagnostic::QueryReadWitness::new(self.lease);
        let witness = witness.unwrap_or(&local);
        let result = async {
            self.check(self.client, &self.frame, self.lease)?;
            fresh_query::fields_impl(
                self.client,
                &self.frame,
                &options.expression,
                options,
                fields,
                self.lease,
                witness,
                Some(self),
            )
            .await
        }
        .await;
        witness.observe(&result);
        result
    }
    // Dispatch completes the transaction's topology fence before this explicit
    // continuation. It cannot re-enter fresh sampling or renew the lease.
    pub(crate) async fn ax_fields(
        &self,
        options: &QueryOptions,
        fields: &[ReadField],
        witness: Option<&query_diagnostic::QueryReadWitness>,
    ) -> Result<Vec<Value>, ObservationError> {
        let local = query_diagnostic::QueryReadWitness::new(self.lease);
        let witness = witness.unwrap_or(&local);
        self.check(self.client, &self.frame, self.lease)?;
        let result = query_fields_ax(
            self.client,
            std::slice::from_ref(&self.frame),
            &self.frame,
            &options.expression,
            options,
            fields,
            self.lease,
            witness,
        )
        .await;
        witness.observe(&result);
        result
    }
}
