//! Platform-local organization invitation contracts.

use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, RwLock};

use sha2::{Digest, Sha256};

/// Prefix used for raw platform invitation tokens.
pub const PLATFORM_INVITATION_TOKEN_PREFIX: &str = "swp_inv_";

/// Organization invitation lifecycle status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformInvitationStatus {
    /// Invitation can be accepted before expiry.
    Pending,
    /// Invitation was accepted and cannot be reused.
    Accepted,
    /// Invitation was revoked before acceptance.
    Revoked,
    /// Invitation exceeded its validity window.
    Expired,
}

impl PlatformInvitationStatus {
    /// Returns the stable status id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    /// Parses a stable status id.
    #[must_use]
    pub fn from_id(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "accepted" => Some(Self::Accepted),
            "revoked" => Some(Self::Revoked),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }

    /// Returns whether the invitation can still be accepted.
    #[must_use]
    pub const fn accepts_at(self, expires_at_unix: i64, now_unix: i64) -> bool {
        matches!(self, Self::Pending) && expires_at_unix > now_unix
    }
}

/// Durable organization invitation metadata. Raw invitation tokens are never stored.
#[derive(Clone, Eq, PartialEq)]
pub struct PlatformOrganizationInvitationRecord {
    /// Stable invitation id.
    pub invitation_id: String,
    /// Owning tenant id.
    pub tenant_id: String,
    /// Target organization id.
    pub organization_id: String,
    /// Optional target project id inside the organization.
    pub project_id: Option<String>,
    /// Optional normalized email target.
    pub invited_email: Option<String>,
    /// Optional principal target.
    pub invited_principal_id: Option<String>,
    /// Hash of the raw invitation token.
    pub invitation_token_hash: String,
    /// Requested role id.
    pub role_id: String,
    /// Invitation status.
    pub status: PlatformInvitationStatus,
    /// Expiry timestamp as unix seconds.
    pub expires_at_unix: i64,
    /// Acceptance timestamp as unix seconds.
    pub accepted_at_unix: Option<i64>,
    /// Creating principal or service actor.
    pub created_by: String,
    /// Optimistic concurrency version.
    pub resource_version: i64,
    /// Creation timestamp as unix seconds.
    pub created_at_unix: i64,
    /// Update timestamp as unix seconds.
    pub updated_at_unix: i64,
}

impl Debug for PlatformOrganizationInvitationRecord {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PlatformOrganizationInvitationRecord")
            .field("invitation_id", &self.invitation_id)
            .field("tenant_id", &self.tenant_id)
            .field("organization_id", &self.organization_id)
            .field("project_id", &self.project_id)
            .field("invited_email", &self.invited_email)
            .field("invited_principal_id", &self.invited_principal_id)
            .field("invitation_token_hash", &"<redacted>")
            .field("role_id", &self.role_id)
            .field("status", &self.status)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("accepted_at_unix", &self.accepted_at_unix)
            .field("created_by", &self.created_by)
            .field("resource_version", &self.resource_version)
            .field("created_at_unix", &self.created_at_unix)
            .field("updated_at_unix", &self.updated_at_unix)
            .finish()
    }
}

/// Request to accept an organization invitation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptPlatformOrganizationInvitationRequest {
    /// Invitation id.
    pub invitation_id: String,
    /// Principal accepting the invitation.
    pub principal_id: String,
    /// Organization membership id to create when needed.
    pub organization_member_id: String,
    /// Project membership id to create when needed.
    pub project_member_id: Option<String>,
    /// Acceptance timestamp.
    pub accepted_at_unix: i64,
}

/// Invitation repository error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformInvitationError {
    /// Invitation id is malformed.
    InvalidInvitationId,
    /// Tenant id is malformed.
    InvalidTenantId,
    /// Organization id is malformed.
    InvalidOrganizationId,
    /// Project id is malformed.
    InvalidProjectId,
    /// Principal id is malformed.
    InvalidPrincipalId,
    /// Creator id is malformed.
    InvalidCreatedBy,
    /// Token hash is malformed.
    InvalidTokenHash,
    /// Email target is malformed.
    InvalidEmail,
    /// Role id is unsupported.
    InvalidRoleId,
    /// Invitation status is unsupported.
    InvalidStatus,
    /// Timestamp is invalid.
    InvalidTimestamp,
    /// Invitation target is missing or ambiguous.
    InvalidTarget,
    /// Resource version is stale.
    StaleResourceVersion,
    /// Invitation is not pending.
    InvitationNotPending,
    /// Invitation cannot be accepted now.
    InvitationNotAccepting,
    /// Authenticated principal does not match the invitation target.
    InvitationPrincipalMismatch,
}

impl PlatformInvitationError {
    /// Returns the stable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInvitationId => "invitation_id_invalid",
            Self::InvalidTenantId => "tenant_id_invalid",
            Self::InvalidOrganizationId => "organization_id_invalid",
            Self::InvalidProjectId => "project_id_invalid",
            Self::InvalidPrincipalId => "principal_id_invalid",
            Self::InvalidCreatedBy => "created_by_invalid",
            Self::InvalidTokenHash => "invitation_token_hash_invalid",
            Self::InvalidEmail => "invitation_email_invalid",
            Self::InvalidRoleId => "invitation_role_invalid",
            Self::InvalidStatus => "invitation_status_invalid",
            Self::InvalidTimestamp => "invitation_timestamp_invalid",
            Self::InvalidTarget => "invitation_target_invalid",
            Self::StaleResourceVersion => "stale_resource_version",
            Self::InvitationNotPending => "invitation_not_pending",
            Self::InvitationNotAccepting => "invitation_not_accepting",
            Self::InvitationPrincipalMismatch => "invitation_principal_mismatch",
        }
    }
}

/// In-memory platform organization invitation store.
#[derive(Clone, Debug, Default)]
pub struct InMemoryPlatformInvitationStore {
    invitations: Arc<RwLock<BTreeMap<String, PlatformOrganizationInvitationRecord>>>,
}

impl InMemoryPlatformInvitationStore {
    /// Creates an empty invitation store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a new invitation.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformInvitationError`] when the record shape is invalid.
    pub fn create_organization_invitation(
        &self,
        record: PlatformOrganizationInvitationRecord,
    ) -> Result<PlatformOrganizationInvitationRecord, PlatformInvitationError> {
        validate_organization_invitation(&record)?;
        write_lock(&self.invitations).insert(record.invitation_id.clone(), record.clone());
        Ok(record)
    }

    /// Lists invitations for one organization.
    #[must_use]
    pub fn organization_invitations(
        &self,
        tenant_id: &str,
        organization_id: &str,
    ) -> Vec<PlatformOrganizationInvitationRecord> {
        let mut invitations = read_lock(&self.invitations)
            .values()
            .filter(|invitation| {
                invitation.tenant_id == tenant_id && invitation.organization_id == organization_id
            })
            .cloned()
            .collect::<Vec<_>>();
        invitations.sort_by(|left, right| {
            right
                .created_at_unix
                .cmp(&left.created_at_unix)
                .then_with(|| left.invitation_id.cmp(&right.invitation_id))
        });
        invitations
    }

    /// Loads an invitation by id.
    #[must_use]
    pub fn organization_invitation(
        &self,
        invitation_id: &str,
    ) -> Option<PlatformOrganizationInvitationRecord> {
        read_lock(&self.invitations).get(invitation_id).cloned()
    }

    /// Loads an invitation by raw-token hash.
    #[must_use]
    pub fn organization_invitation_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Option<PlatformOrganizationInvitationRecord> {
        read_lock(&self.invitations)
            .values()
            .find(|invitation| invitation.invitation_token_hash == token_hash)
            .cloned()
    }

    /// Revokes a pending invitation with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformInvitationError`] when the invitation is missing,
    /// stale, or no longer pending.
    pub fn revoke_organization_invitation(
        &self,
        invitation_id: &str,
        expected_resource_version: i64,
        now_unix: i64,
    ) -> Result<PlatformOrganizationInvitationRecord, PlatformInvitationError> {
        let mut invitations = write_lock(&self.invitations);
        let invitation = invitations
            .get_mut(invitation_id)
            .ok_or(PlatformInvitationError::InvalidInvitationId)?;
        if invitation.resource_version != expected_resource_version {
            return Err(PlatformInvitationError::StaleResourceVersion);
        }
        if invitation.status != PlatformInvitationStatus::Pending {
            return Err(PlatformInvitationError::InvitationNotPending);
        }
        invitation.status = PlatformInvitationStatus::Revoked;
        invitation.resource_version += 1;
        invitation.updated_at_unix = now_unix;
        let revoked = invitation.clone();
        drop(invitations);
        Ok(revoked)
    }

    /// Accepts a pending invitation for a matching principal.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformInvitationError`] when the invitation is missing,
    /// expired, reused, or does not target the principal.
    pub fn accept_organization_invitation(
        &self,
        request: &AcceptPlatformOrganizationInvitationRequest,
    ) -> Result<PlatformOrganizationInvitationRecord, PlatformInvitationError> {
        validate_prefixed_id(
            &request.invitation_id,
            "inv_",
            PlatformInvitationError::InvalidInvitationId,
        )?;
        validate_prefixed_id(
            &request.principal_id,
            "usr_",
            PlatformInvitationError::InvalidPrincipalId,
        )?;
        validate_prefixed_id(
            &request.organization_member_id,
            "om_",
            PlatformInvitationError::InvalidInvitationId,
        )?;
        if let Some(project_member_id) = request.project_member_id.as_deref() {
            validate_prefixed_id(
                project_member_id,
                "pm_",
                PlatformInvitationError::InvalidInvitationId,
            )?;
        }
        if request.accepted_at_unix <= 0 {
            return Err(PlatformInvitationError::InvalidTimestamp);
        }

        let mut invitations = write_lock(&self.invitations);
        let invitation = invitations
            .get_mut(&request.invitation_id)
            .ok_or(PlatformInvitationError::InvalidInvitationId)?;
        if !invitation
            .status
            .accepts_at(invitation.expires_at_unix, request.accepted_at_unix)
        {
            return Err(PlatformInvitationError::InvitationNotAccepting);
        }
        if invitation.invited_principal_id.as_deref() != Some(request.principal_id.as_str()) {
            return Err(PlatformInvitationError::InvitationPrincipalMismatch);
        }
        invitation.status = PlatformInvitationStatus::Accepted;
        invitation.accepted_at_unix = Some(request.accepted_at_unix);
        invitation.resource_version += 1;
        invitation.updated_at_unix = request.accepted_at_unix;
        let accepted = invitation.clone();
        drop(invitations);
        Ok(accepted)
    }
}

/// Hashes a raw platform invitation token.
#[must_use]
pub fn hash_platform_invitation_token(raw_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"starweaver-platform-organization-invitation-v1\0");
    hasher.update(raw_token.trim().as_bytes());
    lower_hex(&hasher.finalize())
}

/// Validates durable organization invitation metadata.
///
/// # Errors
///
/// Returns [`PlatformInvitationError`] when required ids, targets, or status
/// fields are malformed.
pub fn validate_organization_invitation(
    invitation: &PlatformOrganizationInvitationRecord,
) -> Result<(), PlatformInvitationError> {
    validate_prefixed_id(
        &invitation.invitation_id,
        "inv_",
        PlatformInvitationError::InvalidInvitationId,
    )?;
    validate_prefixed_id(
        &invitation.tenant_id,
        "ten_",
        PlatformInvitationError::InvalidTenantId,
    )?;
    validate_prefixed_id(
        &invitation.organization_id,
        "org_",
        PlatformInvitationError::InvalidOrganizationId,
    )?;
    if let Some(project_id) = invitation.project_id.as_deref() {
        validate_prefixed_id(
            project_id,
            "prj_",
            PlatformInvitationError::InvalidProjectId,
        )?;
    }
    let has_email = invitation.invited_email.as_deref().is_some_and(|value| {
        let value = value.trim();
        !value.is_empty() && value.contains('@')
    });
    let has_principal = invitation.invited_principal_id.as_deref().is_some();
    if has_principal {
        validate_prefixed_id(
            invitation
                .invited_principal_id
                .as_deref()
                .unwrap_or_default(),
            "usr_",
            PlatformInvitationError::InvalidPrincipalId,
        )?;
    }
    match (has_email, has_principal) {
        (true, false) | (false, true) => {}
        (true, true) | (false, false) => return Err(PlatformInvitationError::InvalidTarget),
    }
    if invitation.invitation_token_hash.len() != 64
        || !invitation
            .invitation_token_hash
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(PlatformInvitationError::InvalidTokenHash);
    }
    if invitation.role_id.trim().is_empty() {
        return Err(PlatformInvitationError::InvalidRoleId);
    }
    validate_actor_id(&invitation.created_by)?;
    if invitation.expires_at_unix <= 0
        || invitation.created_at_unix <= 0
        || invitation.updated_at_unix <= 0
        || invitation.resource_version <= 0
    {
        return Err(PlatformInvitationError::InvalidTimestamp);
    }
    if invitation.status == PlatformInvitationStatus::Accepted
        && invitation.accepted_at_unix.is_none()
    {
        return Err(PlatformInvitationError::InvalidStatus);
    }
    Ok(())
}

fn validate_actor_id(value: &str) -> Result<(), PlatformInvitationError> {
    if value.starts_with("usr_") || value.starts_with("svc_") || value.starts_with("sys_") {
        Ok(())
    } else {
        Err(PlatformInvitationError::InvalidCreatedBy)
    }
}

fn validate_prefixed_id(
    value: &str,
    prefix: &str,
    error: PlatformInvitationError,
) -> Result<(), PlatformInvitationError> {
    if value.starts_with(prefix) {
        Ok(())
    } else {
        Err(error)
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn read_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::{
        InMemoryPlatformInvitationStore, PlatformInvitationError, PlatformInvitationStatus,
        PlatformOrganizationInvitationRecord, hash_platform_invitation_token,
    };

    #[test]
    fn invitation_status_ids_are_stable() {
        assert_eq!(PlatformInvitationStatus::Pending.as_str(), "pending");
        assert_eq!(
            PlatformInvitationStatus::from_id("accepted"),
            Some(PlatformInvitationStatus::Accepted)
        );
        assert!(PlatformInvitationStatus::Pending.accepts_at(20, 10));
        assert!(!PlatformInvitationStatus::Pending.accepts_at(10, 20));
        assert!(!PlatformInvitationStatus::Revoked.accepts_at(20, 10));
    }

    #[test]
    fn invitation_hash_and_debug_redact_raw_token_material() {
        let token_hash = hash_platform_invitation_token("swp_inv_secret");
        assert_eq!(token_hash.len(), 64);
        let invitation = invitation_record(token_hash);
        let debug = format!("{invitation:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&invitation.invitation_token_hash));
    }

    #[test]
    fn invitation_accept_is_one_time_and_principal_scoped() {
        let store = InMemoryPlatformInvitationStore::new();
        let invitation = store
            .create_organization_invitation(invitation_record(hash_platform_invitation_token(
                "swp_inv_secret",
            )))
            .unwrap_or_else(|error| panic!("invitation should be valid: {error:?}"));

        let wrong = store.accept_organization_invitation(
            &super::AcceptPlatformOrganizationInvitationRequest {
                invitation_id: invitation.invitation_id.clone(),
                principal_id: "usr_other".to_owned(),
                organization_member_id: "om_new".to_owned(),
                project_member_id: Some("pm_new".to_owned()),
                accepted_at_unix: 20,
            },
        );
        assert_eq!(
            wrong,
            Err(PlatformInvitationError::InvitationPrincipalMismatch)
        );

        let accepted = store
            .accept_organization_invitation(&super::AcceptPlatformOrganizationInvitationRequest {
                invitation_id: invitation.invitation_id,
                principal_id: "usr_invited".to_owned(),
                organization_member_id: "om_new".to_owned(),
                project_member_id: Some("pm_new".to_owned()),
                accepted_at_unix: 20,
            })
            .unwrap_or_else(|error| panic!("invitation should accept: {error:?}"));
        assert_eq!(accepted.status, PlatformInvitationStatus::Accepted);
        assert_eq!(accepted.accepted_at_unix, Some(20));

        let replay = store.accept_organization_invitation(
            &super::AcceptPlatformOrganizationInvitationRequest {
                invitation_id: accepted.invitation_id,
                principal_id: "usr_invited".to_owned(),
                organization_member_id: "om_new".to_owned(),
                project_member_id: Some("pm_new".to_owned()),
                accepted_at_unix: 21,
            },
        );
        assert_eq!(replay, Err(PlatformInvitationError::InvitationNotAccepting));
    }

    fn invitation_record(token_hash: String) -> PlatformOrganizationInvitationRecord {
        PlatformOrganizationInvitationRecord {
            invitation_id: "inv_test".to_owned(),
            tenant_id: "ten_test".to_owned(),
            organization_id: "org_test".to_owned(),
            project_id: Some("prj_test".to_owned()),
            invited_email: None,
            invited_principal_id: Some("usr_invited".to_owned()),
            invitation_token_hash: token_hash,
            role_id: "project_developer".to_owned(),
            status: PlatformInvitationStatus::Pending,
            expires_at_unix: 100,
            accepted_at_unix: None,
            created_by: "usr_admin".to_owned(),
            resource_version: 1,
            created_at_unix: 10,
            updated_at_unix: 10,
        }
    }
}
