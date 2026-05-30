"""RFC 1035 binary wire format encode/decode using dnslib."""

import socket as sock_module
from dataclasses import dataclass
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, QTYPE, A as DNS_A


@dataclass
class QueryInfo:
    transaction_id: int
    domain: bytes
    qtype: int
    qclass: int


def encode_query(domain: bytes, qtype: int = QTYPE.A) -> bytes:
    record = DNSRecord(q=DNSQuestion(domain.decode("ascii"), qtype=qtype))
    return bytes(record.pack())


def decode_query(packet: bytes) -> QueryInfo | None:
    try:
        record = DNSRecord.parse(packet)
        if not record.questions:
            return None
        q = record.questions[0]
        domain_str = str(q.qname).rstrip(".")
        return QueryInfo(
            transaction_id=record.header.id,
            domain=domain_str.encode("ascii"),
            qtype=q.qtype,
            qclass=q.qclass,
        )
    except Exception:
        return None


def encode_response(
    info: QueryInfo,
    answers: list[tuple[bytes, int, int, int, bytes]],
) -> bytes:
    rrs = []
    for name, rtype, rclass, ttl, rdata in answers:
        rdata_obj = DNS_A(sock_module.inet_ntoa(rdata)) if rtype == QTYPE.A else rdata
        rrs.append(RR(
            rname=name.decode("ascii"),
            rtype=rtype,
            rclass=rclass,
            ttl=ttl,
            rdata=rdata_obj,
        ))
    header = DNSHeader(
        id=info.transaction_id,
        qr=1, aa=1, ra=0, opcode=0,
        rcode=0,
    )
    record = DNSRecord(
        header=header,
        questions=[DNSQuestion(info.domain.decode("ascii"), qtype=info.qtype, qclass=info.qclass)],
        rr=rrs,
    )
    return bytes(record.pack())


def encode_error(info: QueryInfo, rcode: int) -> bytes:
    header = DNSHeader(
        id=info.transaction_id,
        qr=1, aa=1, ra=0, opcode=0,
        rcode=rcode,
    )
    record = DNSRecord(
        header=header,
        questions=[DNSQuestion(info.domain.decode("ascii"), qtype=info.qtype, qclass=info.qclass)],
    )
    return bytes(record.pack())
