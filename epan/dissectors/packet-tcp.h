/* packet-tcp.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_TCP_H__
#define __PACKET_TCP_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "ws_symbol_export.h"

#include <epan/conversation.h>
#include <epan/wmem/wmem.h>

/* TCP flags */
#define TH_FIN  0x0001
#define TH_SYN  0x0002
#define TH_RST  0x0004
#define TH_PUSH 0x0008
#define TH_ACK  0x0010
#define TH_URG  0x0020
#define TH_ECN  0x0040
#define TH_CWR  0x0080
#define TH_NS   0x0100
#define TH_RES  0x0E00 /* 3 reserved bits */
#define TH_MASK 0x0FFF

/* Idea for gt: either x > y, or y is much bigger (assume wrap) */
#define GT_SEQ(x, y) ((gint32)((y) - (x)) < 0)
#define LT_SEQ(x, y) ((gint32)((x) - (y)) < 0)
#define GE_SEQ(x, y) ((gint32)((y) - (x)) <= 0)
#define LE_SEQ(x, y) ((gint32)((x) - (y)) <= 0)
#define EQ_SEQ(x, y) (x) == (y)

/* mh as in mptcp header */
struct mptcpheader {

	gboolean mh_mpc;    /* true if seen an mp_capable option */
	gboolean mh_join;   /* true if seen an mp_join option */
	gboolean mh_dss;    /* true if seen a dss */
	gboolean mh_fastclose;   /* true if seen a fastclose */
	gboolean mh_fail;   /* true if seen an MP_FAIL */

	guint8  mh_capable_flags; /* to get hmac version for instance */
	guint8  mh_dss_flags; /* data sequence signal flag */
	guint32 mh_ssn; /* Subflow Sequence Number */
	guint64 mh_rawdsn; /* Data Sequence Number */
	guint64 mh_rawack; /* raw data ack */
	guint16 mh_length;  /* mapping/DSS length */

	guint64 mh_key; /* recvkey */
	guint32 mh_token; /* seen in MP_JOIN. Should be a hash of the initial key */

	guint32 mh_stream; /* this stream index field is included to help differentiate when address/port pairs are reused */
};
//mptcp_info_t;

/* the tcp header structure, passed to tap listeners */
typedef struct tcpheader {
	guint32 th_seq;
	guint32 th_ack;
	gboolean th_have_seglen;	/* TRUE if th_seglen is valid */
	guint32 th_seglen;  /* in bytes */
	guint32 th_win;   /* make it 32 bits so we can handle some scaling */
	guint16 th_sport;
	guint16 th_dport;
	guint8  th_hlen;
	guint16 th_flags;
	guint32 th_stream; /* this stream index field is included to help differentiate when address/port pairs are reused */
	address ip_src;
	address ip_dst;

	/* This is the absolute maximum we could find in TCP options (RFC2018, section 3) */
	#define MAX_TCP_SACK_RANGES 4
	guint8  num_sack_ranges;
	guint32 sack_left_edge[MAX_TCP_SACK_RANGES];
	guint32 sack_right_edge[MAX_TCP_SACK_RANGES];

	/* header for TCP option Multipath Operation */
//	mptcp_info_t *th_mptcp;
    struct mptcpheader *th_mptcp;
} tcp_info_t;

/*
 * Private data passed from the TCP dissector to subdissectors.
 */
struct tcpinfo {
	guint32 seq;             /* Sequence number of first byte in the data */
	guint32 nxtseq;          /* Sequence number of first byte after data */
	guint32 lastackseq;      /* Sequence number of last ack */
	gboolean is_reassembled; /* This is reassembled data. */
	gboolean urgent;         /* TRUE if "urgent_pointer" is valid */
	guint16	urgent_pointer;  /* Urgent pointer value for the current packet. */
};

/*
 * Loop for dissecting PDUs within a TCP stream; assumes that a PDU
 * consists of a fixed-length chunk of data that contains enough information
 * to determine the length of the PDU, followed by rest of the PDU.
 *
 * The first three arguments are the arguments passed to the dissector
 * that calls this routine.
 *
 * "proto_desegment" is the dissector's flag controlling whether it should
 * desegment PDUs that cross TCP segment boundaries.
 *
 * "fixed_len" is the length of the fixed-length part of the PDU.
 *
 * "get_pdu_len()" is a routine called to get the length of the PDU from
 * the fixed-length part of the PDU; it's passed "pinfo", "tvb", "offset" and
 * "dissector_data".
 *
 * "dissect_pdu()" is the routine to dissect a PDU.
 */
WS_DLL_PUBLIC void
tcp_dissect_pdus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		 gboolean proto_desegment, guint fixed_len,
		 guint (*get_pdu_len)(packet_info *, tvbuff_t *, int, void*),
		 new_dissector_t dissect_pdu, void* dissector_data);

extern struct tcp_multisegment_pdu *
pdu_store_sequencenumber_of_next_pdu(packet_info *pinfo, guint32 seq, guint32 nxtpdu, wmem_tree_t *multisegment_pdus);

typedef struct _tcp_unacked_t {
	struct _tcp_unacked_t *next;
	guint32 frame;
	guint32	seq;
	guint32	nextseq;
	nstime_t ts;
} tcp_unacked_t;

struct tcp_acked {
	guint32 frame_acked;
	nstime_t ts;

	guint32  rto_frame;
	nstime_t rto_ts;	/* Time since previous packet for
				   retransmissions. */
	guint16 flags; /* see TCP_A_* in packet-tcp.c */
	guint32 dupack_num;	/* dup ack number */
	guint32 dupack_frame;	/* dup ack to frame # */
	guint32 bytes_in_flight; /* number of bytes in flight */
};

/* One instance of this structure is created for each pdu that spans across
 * multiple tcp segments.
 */
struct tcp_multisegment_pdu {
	guint32 seq;
	guint32 nxtpdu;
	guint32 first_frame;
	guint32 last_frame;
	nstime_t last_frame_time;
	guint32 flags;
#define MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT	0x00000001
};

//#if 0
/* One should be able to resegment PDUs across MPTCP connections as well

struct mptcp_multisegment_pdu {
};
*/

/* For now should be used to detect note holes/reinjections
*/
struct mptcp_unacked {
	struct mptcp_unacked *next;

	GSList *mappings; /* mappings that cover this segment */

	//! guint8 subflow number ? or tcp_analysis*
	guint32 frame;

	guint32 frameack;   /* acknowledged in frame */

	guint64	seq;
	guint64	nextseq;
	nstime_t ts;
};

/* can't use GSlist, this is too specific
could use interval binary tree
*/
typedef struct _mptcp_mapping_t {
struct _mptcp_mapping_t *next;
guint64 dsn;  /* Data Sequence Number */
guint32 ssn;  /* Data Sequence Number (relative by definition) */
guint16 length; /* Data level length */
guint32 frame;
nstime_t ts;    /* arrival time */
} mptcp_mapping_t;

/* Should basically look like a_tcp_flow_t but with 64bit sequence number.
 * It has some extra fields to help
 *
 *
 */
typedef struct _mptcp_meta_flow_t {

/*	hmac_algo;    algo used to generate hmacs/tokens */
/*	gboolean checksum_required;    checksum required */

/*	TODO caser un tcp_flow_t et caster en tcp_flow_t
	quand on veut acceder aux champs necessaires ?
	tcp_flow_t
*/
    /* did it initiate the connection ? tristate: dunno/yes/no TODO should be in TCP */
    int client;
	/* flags exchanged between hosts during 3WHS. Gives checksum/extensiblity/hmac information */
	guint8 flags;

//	gboolean enable_dsn_tracking;
	/* TODO check mptcp_get_data_seq_64 */
//	ou bien faire 2 guint32 highorder_basedsn;
    // TODO remove redundant with expected_idsn
	guint64 base_dsn;	/* base data seq number (used by relative sequence numbers) or 0 if not yet known. */
	guint64 nextseq;	/* highest seen nextseq */

	// master tcp stream id  ?
	guint8 version;  /* negociated mptcp version */

// was moved to subflow
// a la limite mettre un pointeur
	guint64 key;    /* if it was set */
	guint32 token;  /* expected token sha1 digest of keys, truncated to 32 most significant bits derived from key. Stored to speed up subflow/MPTCP connection mapping */
//	guint64 expected_token;  /* sha1 digest of keys, truncated to 32 most significant bits derived from key. Stored to speed up subflow/MPTCP connection mapping */
	guint64 expected_idsn;  /* sha1 digest of keys, truncated to 64 LSB */
	guint32 nextseqframe;	/* frame number for segment with highest sequence number */

	guint64 maxseqtobeacked; /* highest seen continuous seq number (without hole in the stream)  */
// TODO keep track of mappings
// RTT
/*	guint32 window;		should be equal to TCP window */
	guint32 fin;		/* frame number of the final FIN */


//	wmem_tree_t *dsn_wraps; /* records frames numbers for which 32bits DSN wrapped. Indexed by frame number */
} mptcp_meta_flow_t;

/* MPTCP data specific to this subflow direction */
struct mptcp_subflow {
	guint32 nonce;  /* used only for MP_JOIN */

//	guint64 *key;    /* */
//	guint32 *token;  /* expected token sha1 digest of keys, truncated to 32 most significant bits derived from key. Stored to speed up subflow/MPTCP connection mapping */


//	gboolean master;
	gboolean backup_flag;   /* */

	guint8 addr_id;   /* address id */
	/* TODO handle mappings */

	GSList *sent_mappings; /* mappings sorted in ssn growing order */

	// TODO should be moved / duplicated to meta ?
	mptcp_mapping_t *infinite_mapping;  /* if datalength == 0 */

	guint32 frame_fallback;   /* frame nb from which connection fell back to infinite mapping */


	/* meta flow to which it is attached. Helps setting forward and backward meta flow */
    mptcp_meta_flow_t *meta;
	/* we are not interested in tracking rcvd mappings yet */
};


typedef enum {
	MPTCP_HMAC_SHA1 = 1
} mptcp_hmac_algorithm_t;

#if 0
/* this should in fact be the meta */
typedef struct _mptcp_flow_t {
	gboolean base_seq_set; /* true if base seq set */
	guint32 base_seq;	/* base seq number (used by relative sequence numbers)*/
	tcp_unacked_t *segments;
	guint32 fin;		/* frame number of the final FIN */
	guint32 lastack;	/* last seen ack */
	nstime_t lastacktime;	/* Time of the last ack packet */
	guint32 lastnondupack;	/* frame number of last seen non dupack */
	guint32 dupacknum;	/* dupack number */
	guint32 nextseq;	/* highest seen nextseq */
	guint32 maxseqtobeacked;/* highest seen continuous seq number (without hole in the stream) from the fwd party,
				 * this is the maximum seq number that can be acked by the rev party in normal case.
				 * If the rev party sends an ACK beyond this seq number it indicates TCP_A_ACK_LOST_PACKET contition */
	guint32 nextseqframe;	/* frame number for segment with highest
				 * sequence number
				 */
	nstime_t nextseqtime;	/* Time of the nextseq packet so we can
				 * distinguish between retransmission,
				 * fast retransmissions and outoforder
				 */
//	guint32 window;		/* last seen window */
//	gint16	win_scale;	/* -1 is we don't know, -2 is window scaling is not used */
//	gint16  scps_capable;   /* flow advertised scps capabilities */
	guint16 maxsizeacked;   /* 0 if not yet known */
//	gboolean valid_bif;     /* if lost pkts, disable BiF until ACK is recvd */

/* This tcp flow/session contains only one single PDU and should
 * be reassembled until the final FIN segment.
 */
//#define TCP_FLOW_REASSEMBLE_UNTIL_FIN	0x0001
	guint16 flags;

	/* see TCP_A_* in packet-tcp.c */
	guint32 lastsegmentflags;

	/* This tree is indexed by sequence number and keeps track of all
	 * all pdus spanning multiple segments for this flow.
	 */
	wmem_tree_t *multisegment_pdus;


    ///////////////////////////////////////////////////////
    // MPTCP ONLY DATA
    ///////////////////////////////////////////////////////
	guint64 key;    /* */
	guint32 token;  /* expected token sha1 digest of keys, truncated to 32 most significant bits derived from key. Stored to speed up subflow/MPTCP connection mapping */

	guint64 base_dsn;	/* base data seq number (used by relative sequence numbers) or 0 if not yet known. */
	guint64 expected_idsn;  /* sha1 digest of keys, truncated to 64 LSB */

    guint8 version;

} mptcp_subflow_t;
#endif

#define MBTCP_CAPABLE_CRYPTO_MASK           0x3F

#define MBTCP_CHECKSUM_MASK                 0x80


typedef struct _tcp_flow_t {
	gboolean base_seq_set; /* true if base seq set */
	guint32 base_seq;	/* base seq number (used by relative sequence numbers)*/
	tcp_unacked_t *segments;
	guint32 fin;		/* frame number of the final FIN */
	guint32 lastack;	/* last seen ack */
	nstime_t lastacktime;	/* Time of the last ack packet */
	guint32 lastnondupack;	/* frame number of last seen non dupack */
	guint32 dupacknum;	/* dupack number */
	guint32 nextseq;	/* highest seen nextseq */
	guint32 maxseqtobeacked;/* highest seen continuous seq number (without hole in the stream) from the fwd party,
				 * this is the maximum seq number that can be acked by the rev party in normal case.
				 * If the rev party sends an ACK beyond this seq number it indicates TCP_A_ACK_LOST_PACKET contition */
	guint32 nextseqframe;	/* frame number for segment with highest
				 * sequence number
				 */
	nstime_t nextseqtime;	/* Time of the nextseq packet so we can
				 * distinguish between retransmission,
				 * fast retransmissions and outoforder
				 */
	guint32 window;		/* last seen window */
	gint16	win_scale;	/* -1 is we don't know, -2 is window scaling is not used */
	gint16  scps_capable;   /* flow advertised scps capabilities */
	guint16 maxsizeacked;   /* 0 if not yet known */
	gboolean valid_bif;     /* if lost pkts, disable BiF until ACK is recvd */

/* This tcp flow/session contains only one single PDU and should
 * be reassembled until the final FIN segment.
 */
#define TCP_FLOW_REASSEMBLE_UNTIL_FIN	0x0001
	guint16 flags;

	/* see TCP_A_* in packet-tcp.c */
	guint32 lastsegmentflags;

	/* This tree is indexed by sequence number and keeps track of all
	 * all pdus spanning multiple segments for this flow.
	 */
	wmem_tree_t *multisegment_pdus;

	/* Process info, currently discovered via IPFIX */
	guint32 process_uid;    /* UID of local process */
	guint32 process_pid;    /* PID of local process */
	gchar *username;	/* Username of the local process */
	gchar *command;         /* Local process name + path + args */

	/* MPTCP subflow intel */
	struct mptcp_subflow *mptcp_subflow;
} tcp_flow_t;

typedef enum {
	MPTCP_CON_SAW_SERVER_ASNWER = 0,  /* if 3WHS prevents 3WHS ACK */
	MPTCP_CON_NO_ALGO_SELECTED,  /* if 3WHS prevents 3WHS ACK or cheksum fails or see MP_FAIL TODO register frame nb where it happens etc...*/
	MPTCP_CON_PENDING,
	MPTCP_CON_INCORRECT,
	MPTCP_CON_OK
} mptcp_connection_state_t;


//typedef struct _mptcp_flowgroup {
//    mptcp_subflow_t flow1;
//    mptcp_subflow_t flow2;
//} mptcp_flowgroup_t;

/* This stores what should be common on both hosts of the MPTCP connection
 * rename into
 * - mptcp_connection
 */
struct mptcp_analysis {

    /* */
	mptcp_connection_state_t state;

	guint16 mp_flags; /* MPTCP meta analysis related, see MPTCP_META_* in packet-tcp.c */

//	guint64 client_key; /* seen in SYN + MP_CAPABLE */
//	guint64 server_key; /* seen in SYN/ACK + MP_CAPABLE */

//    guint8 version; /* Version negotiated */

#if 0
#endif
	/* For the master subflow (MP_CAPABLE), meta_flow1 is used as mptcp->fwd
	 * iff flow1 is used as tcp->fwd
	 *
	 * For other subflows, they link the meta via mptcp_subflow_t::meta_flow
	 * according to the validity of the token.
	 *
	 * meta flows need to be here
	 */
	mptcp_meta_flow_t meta_flow1;
	mptcp_meta_flow_t meta_flow2;


    /* should be accessible from tcp */
	mptcp_meta_flow_t *fwd;
	mptcp_meta_flow_t *rev;

//    mptcp_flowgroup_t* master_flow;

	/* These pointers are set by XXXXX get_tcp_conversation_data()
	 * fwd point in the same direction as the current packet
	 * and rev in the reverse direction
	 */
//	struct mptcp_subflow* fwd;
//	struct mptcp_subflow* rev;

	guint32 stream; /* Keep track of unique mptcp stream (per MP_CAPABLE handshake) */

	/* hmac decided after negociation */
	mptcp_hmac_algorithm_t hmac_algo;

	/* List of subflows,
	(list of tcpd . or tcp_flow_t
	mptcp_flowgroup_t (tracks tcp stream id or tcp_analisys ?)
	move to meta
	*/
	GSList* subflows;

	    /* identifier of the tcp stream that saw the initial 3WHS with MP_CAPABLE option */
	struct tcp_analysis *master;

};

#if 0
struct mptcp_connection {
	mptcp_connection_state_t state;

	guint16 mp_flags; /* MPTCP meta analysis related, see MPTCP_META_* in packet-tcp.c */

	guint64 client_key; /* seen in SYN + MP_CAPABLE */
	guint64 server_key; /* seen in SYN/ACK + MP_CAPABLE */

    guint8 version; /* Version negotiated */

    struct mptcp_analysis* master_flow;

	/* These pointers are set by XXXXX get_tcp_conversation_data()
	 * fwd point in the same direction as the current packet
	 * and rev in the reverse direction
	 */
	struct mptcp_subflow* fwd;
	struct mptcp_subflow* rev;

//    mptcp_flowgroup_t flow;

	/* hmac decided after negociation */
	mptcp_hmac_algorithm_t hmac_algo;
};
#endif

struct tcp_analysis {
	/* These two structs are managed based on comparing the source
	 * and destination addresses and, if they're equal, comparing
	 * the source and destination ports.
	 *
	 * If the source is greater than the destination, then stuff
	 * sent from src is in ual1.
	 *
	 * If the source is less than the destination, then stuff
	 * sent from src is in ual2.
	 *
	 * XXX - if the addresses and ports are equal, we don't guarantee
	 * the behavior.
	 */
	tcp_flow_t	flow1;
	tcp_flow_t	flow2;

	/* These pointers are set by get_tcp_conversation_data()
	 * fwd point in the same direction as the current packet
	 * and rev in the reverse direction
	 */
	tcp_flow_t	*fwd;
	tcp_flow_t	*rev;

	/* This pointer is NULL   or points to a tcp_acked struct if this
	 * packet has "interesting" properties such as being a KeepAlive or
	 * similar
	 */
	struct tcp_acked *ta;
	/* This structure contains a tree containing all the various ta's
	 * keyed by frame number.
	 */
	wmem_tree_t	*acked_table;

	/* Remember the timestamp of the first frame seen in this tcp
	 * conversation to be able to calculate a relative time compared
	 * to the start of this conversation
	 */
	nstime_t	ts_first;

        /* Remember the timestamp of the most recent SYN in this conversation in
         * order to calculate the first_rtt below. Not necessarily ts_first, if
         * the SYN is retransmitted. */
	nstime_t	ts_mru_syn;

        /* If we have the handshake, remember the RTT between the initial SYN
         * and ACK for use detecting out-of-order segments. */
	nstime_t	ts_first_rtt;

	/* Remember the timestamp of the frame that was last seen in this
	 * tcp conversation to be able to calculate a delta time compared
	 * to previous frame in this conversation
	 */
	nstime_t	ts_prev;

	/* Keep track of tcp stream numbers instead of using the conversation
	 * index (as how it was done before). This prevents gaps in the
	 * stream index numbering
	 */
	guint32         stream;

	/* Remembers the server port on the SYN (or SYN|ACK) packet to
	 * help determine which dissector to call
	 */
	guint16 server_port;

    /* allocated only when mptcp enabled
     * several tcp_analysis may refer to the same mptcp_analysis
     * can exist without any meta
     */
	struct mptcp_analysis* mptcp_analysis;
//    struct mptcp_connection* mptcp_connection;
};

/* Structure that keeps per packet data. First used to be able
 * to calculate the time_delta from the last seen frame in this
 * TCP conversation. Can be extended for future use.
 */
struct tcp_per_packet_data_t {
	nstime_t	ts_del;
};


WS_DLL_PUBLIC void dissect_tcp_payload(tvbuff_t *tvb, packet_info *pinfo, int offset,
				guint32 seq, guint32 nxtseq, guint32 sport,
				guint32 dport, proto_tree *tree,
				proto_tree *tcp_tree,
				struct tcp_analysis *tcpd, struct tcpinfo *tcpinfo);

WS_DLL_PUBLIC struct tcp_analysis *get_tcp_conversation_data(conversation_t *conv,
                                packet_info *pinfo);

WS_DLL_PUBLIC gboolean decode_tcp_ports(tvbuff_t *, int, packet_info *, proto_tree *, int, int, struct tcp_analysis *, struct tcpinfo *);

/** Associate process information with a given flow
 *
 * @param frame_num The frame number
 * @param local_addr The local IPv4 or IPv6 address of the process
 * @param remote_addr The remote IPv4 or IPv6 address of the process
 * @param local_port The local TCP port of the process
 * @param remote_port The remote TCP port of the process
 * @param uid The numeric user ID of the process
 * @param pid The numeric PID of the process
 * @param username Ephemeral string containing the full or partial process name
 * @param command Ephemeral string containing the full or partial process name
 */
extern void add_tcp_process_info(guint32 frame_num, address *local_addr, address *remote_addr, guint16 local_port, guint16 remote_port, guint32 uid, guint32 pid, gchar *username, gchar *command);

/** Get the current number of TCP streams
 *
 * @return The number of TCP streams
 */
WS_DLL_PUBLIC guint32 get_tcp_stream_count(void);

/** Get the current number of TCP streams
 *
 * @return The number of TCP streams
 */
WS_DLL_PUBLIC guint32 get_mptcp_stream_count(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
