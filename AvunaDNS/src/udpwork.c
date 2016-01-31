/*
 * udpwork.c
 *
 *  Created on: Jan 30, 2016
 *      Author: root
 */

#include "udpwork.h"
#include "util.h"
#include <sys/socket.h>
#include <netinet/ip.h>
#include "zone.h"
#include "xstring.h"
#include <errno.h>

struct dnsheader {
		uint16_t id;
		uint8_t rd :1;
		uint8_t tc :1;

		uint8_t aa :1;

		uint8_t opcode :4;

		uint8_t QR :1;
		uint8_t rcode :4;
		uint8_t z :3;

		uint8_t ra :1;
		uint16_t qdcount;
		uint16_t ancount;
		uint16_t nscount;
		uint16_t arcount;
};

struct dnsquestion {
		char* domain;
		uint16_t type;
		;uint16_t class;
		// formatting issue is fixed with an extra semicolon?
};

struct dnsrecord {
		char* domain;
		uint16_t type;
		;uint16_t class;
		int32_t ttl;
		uint16_t rdlength;
		unsigned char* rd;
};

char* readDomain(unsigned char* data, size_t* doff, size_t len) {
	int x = 0;
	int i = *doff;
	char* dom = xmalloc(1);
	dom[0] = 0;
	int di = 0;
	int f = 0;
	while (i < len && (x = data[i]) > 0) {
		i++;
		if (!f) *doff = i;
		if ((x & 0xC0) == 0xC0) { // compressed
			i = i & 0x3F;
			f = 1;
		}
		if (i >= len || i < 0) break;
		dom = xrealloc(dom, x + di + 2);
		memcpy(dom + di, data + i, x);
		dom[di + x] = '.';
		dom[di + x + 1] = 0;
		di += x + 1;
		i += x;
		if (!f) *doff = i;
	}
	if (!f) (*doff)++; // account for ending
	dom[di - 1] = 0;
	return dom;
}

void parseZone(struct dnsquestion* dq, struct zone* zone, struct dnsrecord*** rrecs, size_t* rrecsl) {
	int rs = -1;
	struct zoneentry** zee = NULL;
	size_t zeel = 0;
	for (size_t i = 0; i < zone->entry_count; i++) {
		struct zoneentry* ze = zone->entries[i];
		if (ze->type == 0 && domeq(ze->part.subzone->domain, dq->domain) && rs < 0) {
			parseZone(dq, ze->part.subzone, rrecs, rrecsl);
		} else if (ze->type == 1 && domeq(ze->part.dom.domain, dq->domain) && ze->part.dom.type == dq->type) {
			if (rs >= 0) {
				if (zee == NULL) {
					zee = xmalloc(sizeof(struct zoneentry*));
					zeel = 0;
				} else {
					zee = xrealloc(zee, sizeof(struct zoneentry*) * (zeel + 1));
				}
				zee[zeel++] = ze;
			} else {
				if (*rrecs == NULL) {
					*rrecs = xmalloc(sizeof(struct dnsrecord*));
					(*rrecsl) = 0;
				} else {
					*rrecs = xrealloc(*rrecs, sizeof(struct dnsrecord*) * ((*rrecsl) + 1));
				}
				struct dnsrecord* dr = xmalloc(sizeof(struct dnsrecord));
				dr->domain = dq->domain;
				dr->type = ze->part.dom.type;
				dr->class = 1;
				dr->ttl = ze->part.dom.ttl;
				dr->rdlength = ze->part.dom.data_len;
				dr->rd = ze->part.dom.data;
				(*rrecs)[(*rrecsl)++] = dr;
			}
		} else if (ze->type == 2) {
			rs = ze->part.rrst.per;
		} else if (ze->type == 3) {
			if (rs > 0) {
				if (zeel <= rs) {
					for (size_t j = 0; j < zeel; j++) { // TODO: fix code repititon
						struct zoneentry* ze = zee[j];
						if (*rrecs == NULL) {
							*rrecs = xmalloc(sizeof(struct dnsrecord*));
							(*rrecsl) = 0;
						} else {
							*rrecs = xrealloc(*rrecs, sizeof(struct dnsrecord*) * ((*rrecsl) + 1));
						}
						struct dnsrecord* dr = xmalloc(sizeof(struct dnsrecord));
						dr->domain = dq->domain;
						dr->type = ze->part.dom.type;
						dr->class = 1;
						dr->ttl = ze->part.dom.ttl;
						dr->rdlength = ze->part.dom.data_len;
						dr->rd = ze->part.dom.data;
						(*rrecs)[(*rrecsl)++] = dr;
					}
				} else {
					for (size_t j = 0; j < rs; j++) {
						size_t x = rand() % zeel;
						int f = 0;
						for (size_t y = 0; y < zeel; y++) {
							struct zoneentry* zed = zee[x];
							if (zed == NULL) continue;
							zee[x] = NULL;
							if (*rrecs == NULL) {
								*rrecs = xmalloc(sizeof(struct dnsrecord*));
								(*rrecsl) = 0;
							} else {
								*rrecs = xrealloc(*rrecs, sizeof(struct dnsrecord*) * ((*rrecsl) + 1));
							}
							struct dnsrecord* dr = xmalloc(sizeof(struct dnsrecord));
							dr->domain = dq->domain;
							dr->type = zed->part.dom.type;
							dr->class = 1;
							dr->ttl = zed->part.dom.ttl;
							dr->rdlength = zed->part.dom.data_len;
							dr->rd = zed->part.dom.data;
							(*rrecs)[(*rrecsl)++] = dr;
							x++;
							if (x == zeel) x = 0;
							f = 1;
							break;
						}
						if (!f) {
							for (size_t j = 0; j < zeel; j++) {
								struct zoneentry* ze = zee[j];
								if (ze == NULL) break;
								if (*rrecs == NULL) {
									*rrecs = xmalloc(sizeof(struct dnsrecord*));
									(*rrecsl) = 0;
								} else {
									*rrecs = xrealloc(*rrecs, sizeof(struct dnsrecord*) * ((*rrecsl) + 1));
								}
								struct dnsrecord* dr = xmalloc(sizeof(struct dnsrecord));
								dr->domain = dq->domain;
								dr->type = ze->part.dom.type;
								dr->class = 1;
								dr->ttl = ze->part.dom.ttl;
								dr->rdlength = ze->part.dom.data_len;
								dr->rd = ze->part.dom.data;
								(*rrecs)[(*rrecsl)++] = dr;
								break;
							}
						}
					}
				}
			}
			if (zee != NULL) free(zee);
			zee = NULL;
			zeel = 0;

			rs = -1;
		}
	}
}

void writeDomain(char* dom, unsigned char* buf, size_t ml, size_t* cs) {
	size_t sd = strlen(dom);
	if (sd + 2 + *cs > ml) {
		return;
	}
	unsigned char* lb = buf + *cs;
	*lb = 0;
	(*cs)++;
	for (size_t i = 0; i < sd; i++) {
		if (dom[i] == '.') {
			lb = buf + *cs;
			*lb = 0;
		} else {
			(*lb)++;
			buf[*cs] = dom[i];
		}
		(*cs)++;
	}
	buf[(*cs)++] = 0;
}

void handleUDP(struct udpwork_param* param, void* buf, size_t len, struct sockaddr* addr, socklen_t addrl) {
	if (len < 12) return;
	struct dnsheader* head = buf;
	head->qdcount = (head->qdcount >> 8) | ((head->qdcount & 0xff) << 8);
	head->ancount = (head->ancount >> 8) | ((head->ancount & 0xff) << 8);
	head->nscount = (head->nscount >> 8) | ((head->nscount & 0xff) << 8);
	head->arcount = (head->arcount >> 8) | ((head->arcount & 0xff) << 8);
	unsigned char* qrs = buf + 12;
	struct dnsquestion qds[head->qdcount];
	size_t cp = 12;
	for (int i = 0; i < head->qdcount; i++) {
		qds[i].domain = readDomain(buf, &cp, len);
		uint16_t* tt = buf + cp;
		qds[i].type = htons(*tt);
		cp += 2;
		tt = buf + cp;
		qds[i].class = htons(*tt);
		cp += 2;
	}
	//as a authoritative server only, we only need to see up to questions.
	struct dnsheader* rhead = xmalloc(sizeof(struct dnsheader));
	rhead->id = head->id;
	rhead->rd = 0;
	rhead->tc = 0;
	rhead->aa = 1;
	rhead->opcode = 0;
	rhead->QR = 1;
	rhead->rcode = 0;
	rhead->z = 0;
	rhead->ra = 0;
	rhead->qdcount = head->qdcount;
	rhead->ancount = 0;
	rhead->nscount = 0;
	rhead->arcount = 0;
	struct dnsrecord** rrecs = NULL;
	size_t rrecsl = 0;
	if (head->opcode != 0) {
		rhead->rcode = 4;
		goto wr;
	}
	for (int x = 0; x < head->qdcount; x++) {
		parseZone(&qds[x], param->zone, &rrecs, &rrecsl);
	}
	rhead->ancount = rrecsl;
	wr: ;
	rhead->qdcount = htons(rhead->qdcount);
	rhead->ancount = htons(rhead->ancount);
	rhead->nscount = htons(rhead->nscount);
	rhead->arcount = htons(rhead->arcount);
	unsigned char* resp = (unsigned char*) rhead;
	size_t cs = 12;
	for (int i = 0; i < head->qdcount; i++) {
		struct dnsquestion* dq = &(qds[i]);
		size_t al = strlen(dq->domain) + 2 + 4;
		resp = xrealloc(resp, cs + al);
		writeDomain(dq->domain, resp, cs + al, &cs);
		uint16_t tt = htons(dq->type);
		memcpy(resp + cs, &tt, 2);
		cs += 2;
		tt = htons(dq->class);
		memcpy(resp + cs, &tt, 2);
		cs += 2;
	}
	for (int i = 0; i < rrecsl; i++) {
		struct dnsrecord* dr = rrecs[i];
		size_t al = strlen(dr->domain) + 2 + 10 + dr->rdlength;
		resp = xrealloc(resp, cs + al);
		writeDomain(dr->domain, resp, cs + al, &cs);
		uint16_t t = htons(dr->type);
		memcpy(resp + cs, &t, 2);
		cs += 2;
		t = htons(dr->class);
		memcpy(resp + cs, &t, 2);
		cs += 2;
		int32_t ttl = htonl(dr->ttl);
		memcpy(resp + cs, &ttl, 4);
		cs += 4;
		t = htons(dr->rdlength);
		memcpy(resp + cs, &t, 2);
		cs += 2;
		memcpy(resp + cs, dr->rd, dr->rdlength);
		cs += dr->rdlength;
	}
	sendto(param->sfd, resp, cs, 0, addr, addrl);
}

void run_udpwork(struct udpwork_param* param) {
	unsigned char* mbuf = xmalloc(512); // udp has a maximum of 512
	struct sockaddr addr; //TODO: ipv6?
	socklen_t addrl = sizeof(struct sockaddr);
	while (1) {
		int x = recvfrom(param->sfd, mbuf, 512, 0, (struct sockaddr*) &addr, &addrl);
		if (x < 0) continue; // this shouldnt happen
		if (x > 0) {
			handleUDP(param, mbuf, x, &addr, addrl);
		}
	}
	xfree(mbuf);
}
