//! Groups decides consent and membership; Threads owns the shared MLS commit.
use crate::{Error, Inbox, Result};
use cwst::{Store, backend::Backend};

/// Loaded owner snapshots. No caller-supplied roster or snapshot is accepted.
pub struct GroupConversation {
    group: cgrp::Id,
    groups: cgrp::Snapshot,
    threads: cthr::Threads,
}

/// Wire inputs for the original Threads operation. Groups independently
/// authenticates the corresponding request and all required signed consents.
pub enum GroupAction<'a> {
    Create { packages: &'a [Vec<u8>] },
    Join { welcome: &'a [u8] },
    Update,
}

/// Matching candidates remain private until one original compound Store CAS.
pub struct PreparingGroup {
    groups: cgrp::Candidate,
    threads: cthr::Candidate,
    operation: cgrp::Id,
}

pub struct GroupPublication {
    groups: cgrp::Snapshot,
    threads: cthr::Committed,
    effects: Vec<cgrp::CommittedEffect>,
}

impl Inbox {
    pub fn group<B: Backend>(
        &self,
        group: cgrp::Id,
        store: &Store<B>,
    ) -> Result<GroupConversation> {
        Ok(GroupConversation {
            group,
            groups: cgrp::Snapshot::load(self.binding.community(), store).map_err(Error::Groups)?,
            threads: cthr::Threads::load(self.binding.clone(), group, store)
                .map_err(Error::Threads)?,
        })
    }
}

impl GroupConversation {
    pub fn revision(&self) -> u64 {
        self.groups.revision()
    }

    pub fn group_state(&self) -> Result<cgrp::GroupState> {
        self.groups.group_state(&self.group).map_err(Error::Groups)
    }

    /// Original canonical predecessor references, suitable for requesting
    /// consent. Returning metadata alone grants no authority to import it.
    pub fn parent_references(&self, command: &cgrp::Command) -> Result<Vec<cgrp::ParentRef>> {
        self.groups
            .parent_references(command)
            .map_err(Error::Groups)
    }

    pub async fn parent_evidence<B: Backend>(
        &self,
        keys: &mut impl cthr::keys::Custody,
        store: &Store<B>,
        policy: &impl cgrp::PolicySource,
        clock: &mut impl ckmg::Clock,
    ) -> Result<cthr::ParentEvidence> {
        self.threads
            .parent_evidence(keys, store, policy, clock)
            .await
            .map_err(Error::Threads)
    }

    pub fn snapshot(&self, policy: &impl cgrp::PolicySource, now: u64) -> Result<cgrp::GroupView> {
        let policy = policy
            .current(self.groups.community(), now)
            .map_err(Error::Groups)?;
        cgrp::view(&self.groups, &self.group, &policy, now).map_err(Error::Groups)
    }

    pub async fn prepare(
        &self,
        request: &cgrp::Request,
        action: GroupAction<'_>,
        keys: &mut impl cthr::keys::Custody,
        governance: (&impl cgrp::PolicySource, &impl cgrp::Authority),
        clock: &mut impl ckmg::Clock,
        max_groups: usize,
    ) -> Result<PreparingGroup> {
        let now = clock
            .now()
            .map_err(|_| Error::Threads(cthr::Error::Clock))?;
        let groups = cgrp::prepare(
            &self.groups,
            request,
            governance.0,
            governance.1,
            now,
            max_groups,
        )
        .map_err(Error::Groups)?;
        let effects = groups.prepare_effects();
        let decision = effects.iter().find(|effect| {
            matches!(effect.event(), cgrp::Effect::Membership { group, .. } if group == &self.group)
        }).ok_or(Error::Groups(cgrp::Error::Authority))?;
        let threads = match action {
            GroupAction::Create { packages } => {
                self.threads
                    .create_fork(keys, decision, packages, clock)
                    .await
            }
            GroupAction::Join { welcome } => {
                self.threads.join_fork(keys, decision, welcome, clock).await
            }
            GroupAction::Update => self.threads.update_fork(keys, decision, clock).await,
        }
        .map_err(Error::Threads)?;
        Ok(PreparingGroup {
            groups,
            threads,
            operation: request.operation,
        })
    }
}

impl PreparingGroup {
    /// Current device and Groups authority are repeated by Threads after its
    /// asynchronous custody checks, immediately before the combined checkpoint.
    pub async fn commit<B: Backend>(
        self,
        keys: &mut impl cthr::keys::Custody,
        store: &mut Store<B>,
        governance: (&impl cgrp::PolicySource, &impl cgrp::Authority),
        clock: &mut impl ckmg::Clock,
    ) -> Result<GroupPublication> {
        let (threads, groups, effects) = self
            .threads
            .commit_groups(keys, self.groups, store, self.operation, governance, clock)
            .await
            .map_err(Error::Threads)?;
        Ok(GroupPublication {
            groups,
            threads,
            effects,
        })
    }
}

impl GroupPublication {
    pub fn revision(&self) -> u64 {
        self.groups.revision()
    }

    pub fn events(&self) -> &[cthr::Event] {
        self.threads.events()
    }

    pub fn effects(&self) -> &[cgrp::CommittedEffect] {
        &self.effects
    }
}
