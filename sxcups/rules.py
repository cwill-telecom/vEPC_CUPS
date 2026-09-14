# cups/rules.py — the four Sx rule types provisioned by the CPF in the UPF.
#
#   PDR  Packet Detection Rule      – which packets receive a treatment
#   FAR  Forwarding Action Rule     – apply action: forward/duplicate/buffer/drop/notify
#   QER  QoS Enforcement Rule       – QoS policing (MBR/GBR, QFI)
#   URR  Usage Reporting Rule       – measure & report traffic usage
#   BAR  Buffering Action Rule      – used by FAR when Apply Action = BUFFER
from protocols import pfcp

_IFACE_NAME = {0: "Access", 1: "Core", 2: "SGi-LAN", 3: "CP-Function"}


class PDR:
    def __init__(self, pdr_id, precedence=100, source_interface="Access",
                 fteid=None, network_instance="", urr_ids=(), qer_ids=(), far_id=None):
        self.pdr_id = pdr_id
        self.precedence = precedence
        self.source_interface = source_interface   # Access | Core | SGi-LAN | CP-Function
        self.fteid = fteid                          # (teid, ip) local F-TEIDu for UL
        self.network_instance = network_instance
        self.urr_ids = list(urr_ids)
        self.qer_ids = list(qer_ids)
        self.far_id = far_id

    def to_pfcp(self):
        src = {"Access": 0, "Core": 1, "SGi-LAN": 2, "CP-Function": 3}.get(
            self.source_interface, 0)
        children = [
            pfcp.ie_pdr_id(self.pdr_id),
            pfcp.encode_ie(pfcp.IE["Precedence"], pfcp._u32(self.precedence)),
            pfcp.encode_grouped(pfcp.IE["PDI"], [pfcp.ie_source_interface(src)]),
        ]
        if self.fteid:
            teid, ip = self.fteid
            children.append(pfcp.encode_grouped(
                pfcp.IE["PDI"], [pfcp.ie_ft_eid(teid, ip)]))
        if self.network_instance:
            children.append(pfcp.encode_ie(
                pfcp.IE["Network Instance"], self.network_instance.encode()))
        for u in self.urr_ids:
            children.append(pfcp.ie_urr_id(u))
        for q in self.qer_ids:
            children.append(pfcp.ie_qer_id(q))
        if self.far_id is not None:
            children.append(pfcp.ie_far_id(self.far_id))
        return pfcp.encode_grouped(pfcp.IE["Create PDR"], children)

    @classmethod
    def from_pfcp(cls, value):
        kids = pfcp.decode_ies_recursive(value)
        pdr = cls(0, source_interface=None)
        for t, v, ch in kids:
            name = pfcp._IE_NAME.get(t, "")
            if name == "PDR ID":
                pdr.pdr_id = pfcp.pdr_id_of(v)
            elif name == "Precedence":
                pdr.precedence = pfcp.u32_of(v)
            elif name == "FAR ID":
                pdr.far_id = pfcp.u32_of(v)
            elif name == "URR ID":
                pdr.urr_ids.append(pfcp.u32_of(v))
            elif name == "QER ID":
                pdr.qer_ids.append(pfcp.u32_of(v))
            elif name == "PDI":
                for ct, cv, cch in ch:
                    cn = pfcp._IE_NAME.get(ct, "")
                    if cn == "F-TEID":
                        pdr.fteid = pfcp.decode_ft_eid(cv)
                    elif cn == "Source Interface":
                        pdr.source_interface = _IFACE_NAME.get(
                            pfcp.u8_of(cv), "Access")
        if pdr.source_interface is None:
            pdr.source_interface = "Access"
        return pdr


class FAR:
    def __init__(self, far_id, apply_action=("FORWARD",), destination_interface="Core",
                 outer_header=(None, None)):
        self.far_id = far_id
        self.apply_action = list(apply_action)
        self.destination_interface = destination_interface
        self.outer_header = outer_header   # (teid, ip) for Outer Header Creation

    def to_pfcp(self):
        dst = {"Access": 0, "Core": 1, "SGi-LAN": 2, "CP-Function": 3}.get(
            self.destination_interface, 1)
        fwd = [pfcp.encode_ie(pfcp.IE["Destination Interface"], pfcp._u8(dst))]
        if self.outer_header and self.outer_header[0] is not None:
            teid, ip = self.outer_header
            fwd.append(pfcp.encode_ie(
                pfcp.IE["Outer Header Creation"],
                pfcp._u16(0x0100) + pfcp._u32(teid) + pfcp._u16(0) +
                __import__("socket").inet_aton(ip)))
        children = [
            pfcp.ie_far_id(self.far_id),
            pfcp.ie_apply_action(
                forward="FORWARD" in self.apply_action,
                drop="DROP" in self.apply_action,
                buffer="BUFFER" in self.apply_action,
                notify="NOTIFY" in self.apply_action,
                duplicate="DUPLICATE" in self.apply_action),
            pfcp.encode_grouped(pfcp.IE["Forwarding Parameters"], fwd),
        ]
        return pfcp.encode_grouped(pfcp.IE["Create FAR"], children)

    @classmethod
    def from_pfcp(cls, value):
        kids = pfcp.decode_ies_recursive(value)
        far = cls(0)
        for t, v, ch in kids:
            name = pfcp._IE_NAME.get(t, "")
            if name == "FAR ID":
                far.far_id = pfcp.u32_of(v)
            elif name == "Apply Action":
                far.apply_action = pfcp.decode_apply_action(v)
        return far


class QER:
    def __init__(self, qer_id, qfi=9, mbr_ul=0, mbr_dl=0):
        self.qer_id = qer_id
        self.qfi = qfi
        self.mbr_ul = mbr_ul
        self.mbr_dl = mbr_dl

    def to_pfcp(self):
        # QFI IE (type 124) + MBR (type 26) omitted for brevity; ids only
        return pfcp.encode_grouped(pfcp.IE["Create QER"], [pfcp.ie_qer_id(self.qer_id)])

    @classmethod
    def from_pfcp(cls, value):
        for t, v, ch in pfcp.decode_ies_recursive(value):
            if pfcp._IE_NAME.get(t) == "QER ID":
                return cls(pfcp.u32_of(v))
        return cls(0)


class URR:
    def __init__(self, urr_id, measurement="VOLUME", triggers=("PERIODIC",),
                 period=60):
        self.urr_id = urr_id
        self.measurement = measurement
        self.triggers = list(triggers)
        self.period = period

    def to_pfcp(self):
        children = [pfcp.ie_urr_id(self.urr_id)]
        children.append(pfcp.encode_ie(pfcp.IE["Measurement Period"],
                                       pfcp._u32(self.period)))
        return pfcp.encode_grouped(pfcp.IE["Create URR"], children)

    @classmethod
    def from_pfcp(cls, value):
        urr = cls(0)
        for t, v, ch in pfcp.decode_ies_recursive(value):
            if pfcp._IE_NAME.get(t) == "URR ID":
                urr.urr_id = pfcp.u32_of(v)
            elif pfcp._IE_NAME.get(t) == "Measurement Period":
                urr.period = pfcp.u32_of(v)
        return urr
