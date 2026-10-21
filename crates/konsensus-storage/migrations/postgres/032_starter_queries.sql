-- Indexed request lookups, bounded recovery/status pages, and requester pruning.
CREATE INDEX starter_grants_requester_time ON starter_grants(requester_node_id, created_at DESC, request_id DESC);
CREATE INDEX starter_grants_work ON starter_grants(request_id) WHERE state IN ('admitted','opening','resolved');
CREATE INDEX starter_grants_invite ON starter_grants(invite_id);
CREATE INDEX starter_grants_recent ON starter_grants(updated_at, request_id);
CREATE INDEX starter_grants_inflight ON starter_grants(state) WHERE state IN ('admitted','opening');
CREATE INDEX starter_grants_committed ON starter_grants(capacity_sats) WHERE state <> 'refused';
CREATE INDEX starter_grants_day ON starter_grants(utc_day) WHERE state <> 'refused';
CREATE INDEX starter_invites_requester ON invites_issued(invitee_pubkey, state, created_at DESC);
CREATE INDEX starter_invites_unsettled ON invites_issued(state, id) WHERE state IN ('pending','opening');
-- Upgrade old installations too: keep only the newest refusal per requester.
DELETE FROM starter_grants WHERE request_id IN (
 SELECT request_id FROM (
  SELECT request_id, ROW_NUMBER() OVER (PARTITION BY requester_node_id ORDER BY created_at DESC, request_id DESC) AS rank
  FROM starter_grants WHERE state='refused'
 ) ranked WHERE rank > 1
);
-- A live reservation already supplies the throttle and replay response.
DELETE FROM starter_grants WHERE state='refused' AND requester_node_id IN (
 SELECT requester_node_id FROM starter_grants WHERE state<>'refused'
);
