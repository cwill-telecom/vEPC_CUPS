-- database_setup.sql — optional MySQL schema for the CUPS vEPC simulator.
--
-- The simulator runs fully in-memory; this schema is provided for parity with
-- vEPC_python's database_setup.sql, if you want to persist Sx sessions/rules.

CREATE DATABASE IF NOT EXISTS cups;
USE cups;

-- One row per Sx session (per PDN connection / IP-CAN session / standalone session).
CREATE TABLE IF NOT EXISTS sx_session (
    session_id   BIGINT      PRIMARY KEY,   -- CPF-assigned Session ID (F-SEID)
    cp_node_id   VARCHAR(45) NOT NULL,      -- CPF Node ID (IPv4/IPv6)
    up_node_id   VARCHAR(45) NOT NULL,      -- UPF Node ID
    kind         VARCHAR(16) NOT NULL,      -- 'PDN' | 'IP-CAN' | 'standalone'
    state        VARCHAR(16) NOT NULL,      -- ESTABLISHED | PENDING
    uplink_bytes BIGINT      DEFAULT 0,
    downlink_bytes BIGINT    DEFAULT 0,
    created_ts   TIMESTAMP   DEFAULT CURRENT_TIMESTAMP
);

-- Sx sessions provisioned by the CPF on the UPF (PDR/FAR/QER/URR ids as JSON).
CREATE TABLE IF NOT EXISTS sx_rules (
    session_id   BIGINT      NOT NULL,
    pdr_ids      VARCHAR(255),               -- e.g. '1,2,9'
    far_ids      VARCHAR(255),
    qer_ids      VARCHAR(255),
    urr_ids      VARCHAR(255),
    FOREIGN KEY (session_id) REFERENCES sx_session(session_id) ON DELETE CASCADE
);

-- Configured PFCP peers (zone default gateway pfcp-peer / *-pfcp-peer-list).
CREATE TABLE IF NOT EXISTS pfcp_peer (
    peer_ip      VARCHAR(45) NOT NULL,
    peer_port    INT         DEFAULT 8805,
    node_type    VARCHAR(16) NOT NULL,        -- 'CPF' | 'UPF'
    iface        VARCHAR(8)  NOT NULL,        -- 'Sxa' | 'Sxb'
    PRIMARY KEY (peer_ip, iface)
);
