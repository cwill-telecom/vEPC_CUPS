# cups/reporting.py — Sx Report (node- and session-level) helpers.
from protocols import pfcp

# Reporting triggers (subset of Usage Report Trigger values, TS 29.244 §8.2.86)
TRIG_PERIODIC            = 0x0001
TRIG_VOLUME_THRESHOLD    = 0x0002
TRIG_TIME_THRESHOLD      = 0x0004
TRIG_QUOTA_EXHAUSTED     = 0x0008
TRIG_START_OF_TRAFFIC    = 0x0010
TRIG_STOP_OF_TRAFFIC     = 0x0020
TRIG_FIRST_DL_DATA       = 0x0040   # detection of 1st downlink data for idle UE

TRIGGER_NAMES = {
    TRIG_PERIODIC: "PERIODIC", TRIG_VOLUME_THRESHOLD: "VOLUME_THRESHOLD",
    TRIG_TIME_THRESHOLD: "TIME_THRESHOLD", TRIG_QUOTA_EXHAUSTED: "QUOTA_EXHAUSTED",
    TRIG_START_OF_TRAFFIC: "START_OF_TRAFFIC", TRIG_STOP_OF_TRAFFIC: "STOP_OF_TRAFFIC",
    TRIG_FIRST_DL_DATA: "FIRST_DOWNLINK_DATA",
}


def build_report_request(seid, seq, triggers, urr_id=None, volume=None, pdr_id=None):
    """Construct a PFCP Session Report Request body.

    `triggers` is a bitmask; `volume` is (total, ul, dl); `pdr_id` used by the
    start/stop-of-traffic and 1st-DL-data reports.
    """
    m = pfcp.Message(pfcp.SESSION_REPORT_REQUEST, seid=seid, seq=seq)
    m.add(pfcp.encode_ie(pfcp.IE["Report Type"], pfcp._u8(triggers & 0xFF)))
    if urr_id is not None:
        urr_group = [pfcp.ie_urr_id(urr_id)]
        if volume:
            total, ul, dl = volume
            # Reported URR -> Volume Measurement
            urr_group.append(pfcp.ie_volume(total, ul, dl))
        m.add(pfcp.encode_ie(pfcp.IE["Report Type"], pfcp._u8(triggers & 0xFF)))
        m.add(pfcp.encode_grouped(pfcp.IE["Create URR"], urr_group))
    if pdr_id is not None:
        m.add(pfcp.encode_grouped(pfcp.IE["Created PDR"], [pfcp.ie_pdr_id(pdr_id)]))
    return m


def describe(trigger_bits):
    return [TRIGGER_NAMES[b] for b in
            (TRIG_PERIODIC, TRIG_VOLUME_THRESHOLD, TRIG_TIME_THRESHOLD,
             TRIG_QUOTA_EXHAUSTED, TRIG_START_OF_TRAFFIC, TRIG_STOP_OF_TRAFFIC,
             TRIG_FIRST_DL_DATA) if trigger_bits & b]
