package za.co.guardpulse.shield

/** A DNS query lifted out of an IPv4/UDP packet read from the tunnel. */
class DnsQuery(
    val srcIp: ByteArray,
    val dstIp: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    val dns: ByteArray,
)

/** Just enough IPv4/UDP/DNS to filter lookups - the tunnel only ever carries DNS. */
object Packets {
    private const val UDP = 17
    private const val DNS_HEADER = 12

    fun parse(buf: ByteArray, len: Int): DnsQuery? {
        if (len < 20 + 8 + DNS_HEADER) return null
        if ((buf[0].toInt() ushr 4) and 0xF != 4) return null
        val ihl = (buf[0].toInt() and 0xF) * 4
        if (ihl < 20 || buf[9].toInt() and 0xFF != UDP) return null
        val total = u16(buf, 2)
        if (total > len) return null
        if (u16(buf, 6) and 0x3FFF != 0) return null // fragmented
        val srcPort = u16(buf, ihl)
        val dstPort = u16(buf, ihl + 2)
        if (dstPort != 53) return null
        val dnsStart = ihl + 8
        val dnsLen = u16(buf, ihl + 4) - 8
        if (dnsLen < DNS_HEADER || dnsStart + dnsLen > total) return null
        return DnsQuery(
            srcIp = buf.copyOfRange(12, 16),
            dstIp = buf.copyOfRange(16, 20),
            srcPort = srcPort,
            dstPort = dstPort,
            dns = buf.copyOfRange(dnsStart, dnsStart + dnsLen),
        )
    }

    /** Wrap a DNS reply in IPv4/UDP addressed back to whoever asked. */
    fun reply(q: DnsQuery, dns: ByteArray): ByteArray {
        val total = 20 + 8 + dns.size
        val out = ByteArray(total)
        out[0] = 0x45
        put16(out, 2, total)
        put16(out, 6, 0x4000) // don't fragment
        out[8] = 64
        out[9] = UDP.toByte()
        System.arraycopy(q.dstIp, 0, out, 12, 4)
        System.arraycopy(q.srcIp, 0, out, 16, 4)
        put16(out, 10, checksum(out, 0, 20))
        put16(out, 20, q.dstPort)
        put16(out, 22, q.srcPort)
        put16(out, 24, 8 + dns.size)
        // UDP checksum 0 = "not computed", valid for IPv4
        System.arraycopy(dns, 0, out, 28, dns.size)
        return out
    }

    /** First question's name, e.g. "www.example.com", or null if malformed. */
    fun qname(dns: ByteArray): String? = questionEnd(dns)?.let { end ->
        val labels = mutableListOf<String>()
        var i = DNS_HEADER
        while (i < end - 4) {
            val n = dns[i].toInt() and 0xFF
            if (n == 0) break
            labels += String(dns, i + 1, n, Charsets.US_ASCII)
            i += n + 1
        }
        labels.joinToString(".").lowercase()
    }

    fun nxdomain(query: ByteArray): ByteArray? = answerWithRcode(query, 3)

    fun servfail(query: ByteArray): ByteArray? = answerWithRcode(query, 2)

    /** Header + first question, flagged as a response with ``rcode`` and no answers. */
    private fun answerWithRcode(query: ByteArray, rcode: Int): ByteArray? {
        val end = questionEnd(query) ?: return null
        val out = query.copyOfRange(0, end)
        out[2] = ((out[2].toInt() or 0x80) and 0xF9).toByte() // QR=1, AA=0, TC=0, keep opcode + RD
        out[3] = (0x80 or rcode).toByte() // RA=1
        put16(out, 4, 1)
        put16(out, 6, 0)
        put16(out, 8, 0)
        put16(out, 10, 0)
        return out
    }

    /** Offset just past the first question (name + qtype + qclass). Pointers aren't legal here. */
    private fun questionEnd(dns: ByteArray): Int? {
        if (dns.size < DNS_HEADER + 5 || u16(dns, 4) < 1) return null
        var i = DNS_HEADER
        while (i < dns.size) {
            val n = dns[i].toInt() and 0xFF
            if (n == 0) return if (i + 5 <= dns.size) i + 5 else null
            if (n and 0xC0 != 0) return null
            i += n + 1
        }
        return null
    }

    private fun checksum(b: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        var i = off
        while (i < off + len) {
            sum += u16(b, i)
            i += 2
        }
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)

    private fun put16(b: ByteArray, i: Int, v: Int) {
        b[i] = (v ushr 8).toByte()
        b[i + 1] = v.toByte()
    }
}
