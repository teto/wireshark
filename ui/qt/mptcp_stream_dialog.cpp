/* mptcp_stream_dialog.cpp
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

#include "mptcp_stream_dialog.h"
#include <ui_mptcp_stream_dialog.h>

#include <algorithm> // for std::sort
#include <utility> // for std::pair
#include <vector>

#include "epan/to_str.h"

#include "wsutil/str_util.h"

#include <wsutil/utf8_entities.h>

#include <ui/qt/utils/tango_colors.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include "progress_frame.h"
#include "wireshark_application.h"

#include <QCursor>
#include <QDir>
#include <QFileDialog>
#include <QIcon>
#include <QPushButton>

#include <QDebug>

// The GTK+ version computes a 20 (or 21!) segment moving average. Comment
// out the line below to use that. By default we use a 1 second MA.
#define MA_1_SECOND

#ifndef MA_1_SECOND
const int moving_avg_period_ = 20;
#endif


const QRgb graph_color_1 = tango_sky_blue_5;
const QRgb graph_color_2 = tango_butter_6;
const QRgb graph_color_3 = tango_chameleon_5;
const QRgb graph_color_4 = tango_scarlet_red_4;
const QRgb graph_color_5 = tango_scarlet_red_6;

// Size of selectable packet points in the base graph
const double pkt_point_size_ = 3.0;

// Don't accidentally zoom into a 1x1 rect if you happen to click on the graph
// in zoom mode.
const int min_zoom_pixels_ = 20;

const QString average_throughput_label_ = QObject::tr("Average Throughput (bits/s)");
const QString round_trip_time_ms_label_ = QObject::tr("Round Trip Time (ms)");
const QString segment_length_label_ = QObject::tr("Segment Length (B)");
const QString sequence_number_label_ = QObject::tr("Sequence Number (B)");
const QString time_s_label_ = QObject::tr("Time (s)");
const QString window_size_label_ = QObject::tr("Window Size (B)");

MPTCPStreamDialog::MPTCPStreamDialog(QWidget *parent, capture_file *cf, tcp_graph_type graph_type) :
    TCPStreamDialog(parent, cf, graph_type),
    /* QDialog(NULL, Qt::Window), */
    ui(new Ui::MPTCPStreamDialog)
    /* cap_file_(cf), */
    /* ts_offset_(0), */
    /* ts_origin_conn_(true), */
    /* seq_offset_(0), */
    /* seq_origin_zero_(true), */
    /* title_(NULL), */
    /* base_graph_(NULL), */
    /* tput_graph_(NULL), */
    /* goodput_graph_(NULL), */
    /* seg_graph_(NULL), */
    /* ack_graph_(NULL), */
    /* sack_graph_(NULL), */
    /* sack2_graph_(NULL), */
    /* rwin_graph_(NULL), */
    /* tracer_(NULL), */
    /* packet_num_(0), */
    /* mouse_drags_(true), */
    /* rubber_band_(NULL), */
    /* graph_updater_(this), */
    /* num_dsegs_(-1), */
    /* num_acks_(-1), */
    /* num_sack_ranges_(-1), */
    /* ma_window_size_(1.0) */
{
    struct segment current;
    int graph_idx = -1;

    ui->setupUi(this);
    setAttribute(Qt::WA_DeleteOnClose, true);

    graph_.type = GRAPH_UNDEFINED;
    set_address(&graph_.src_address, AT_NONE, 0, NULL);
    graph_.src_port = 0;
    set_address(&graph_.dst_address, AT_NONE, 0, NULL);
    graph_.dst_port = 0;
    graph_.stream = 0;
    graph_.segments = NULL;

    struct tcpheader *header = select_tcpip_session(cap_file_, &current);
    if (!header) {
        done(QDialog::Rejected);
        return;
    }

//#ifdef Q_OS_MAC
//    ui->hintLabel->setAttribute(Qt::WA_MacSmallSize, true);
//#endif

    QComboBox *gtcb = ui->graphTypeComboBox;
    gtcb->setUpdatesEnabled(false);
    gtcb->addItem(ui->actionRoundTripTime->text(), GRAPH_RTT);
    if (graph_type == GRAPH_RTT) graph_idx = gtcb->count() - 1;
    gtcb->addItem(ui->actionThroughput->text(), GRAPH_THROUGHPUT);
    if (graph_type == GRAPH_THROUGHPUT) graph_idx = gtcb->count() - 1;
    gtcb->addItem(ui->actionStevens->text(), GRAPH_TSEQ_STEVENS);
    if (graph_type == GRAPH_TSEQ_STEVENS) graph_idx = gtcb->count() - 1;
    gtcb->addItem(ui->actionTcptrace->text(), GRAPH_TSEQ_TCPTRACE);
    if (graph_type == GRAPH_TSEQ_TCPTRACE) graph_idx = gtcb->count() - 1;
    gtcb->addItem(ui->actionWindowScaling->text(), GRAPH_WSCALE);
    if (graph_type == GRAPH_WSCALE) graph_idx = gtcb->count() - 1;
    gtcb->setUpdatesEnabled(true);

    ui->dragRadioButton->setChecked(mouse_drags_);

    ctx_menu_.addAction(ui->actionZoomIn);
    ctx_menu_.addAction(ui->actionZoomInX);
    ctx_menu_.addAction(ui->actionZoomInY);
    ctx_menu_.addAction(ui->actionZoomOut);
    ctx_menu_.addAction(ui->actionZoomOutX);
    ctx_menu_.addAction(ui->actionZoomOutY);
    ctx_menu_.addAction(ui->actionReset);
    ctx_menu_.addSeparator();
    ctx_menu_.addAction(ui->actionMoveRight10);
    ctx_menu_.addAction(ui->actionMoveLeft10);
    ctx_menu_.addAction(ui->actionMoveUp10);
    ctx_menu_.addAction(ui->actionMoveDown10);
    ctx_menu_.addAction(ui->actionMoveRight1);
    ctx_menu_.addAction(ui->actionMoveLeft1);
    ctx_menu_.addAction(ui->actionMoveUp1);
    ctx_menu_.addAction(ui->actionMoveDown1);
    ctx_menu_.addSeparator();
    ctx_menu_.addAction(ui->actionNextStream);
    ctx_menu_.addAction(ui->actionPreviousStream);
    ctx_menu_.addAction(ui->actionSwitchDirection);
    ctx_menu_.addAction(ui->actionGoToPacket);
    ctx_menu_.addSeparator();
    ctx_menu_.addAction(ui->actionDragZoom);
    ctx_menu_.addAction(ui->actionToggleSequenceNumbers);
    ctx_menu_.addAction(ui->actionToggleTimeOrigin);
    ctx_menu_.addAction(ui->actionCrosshairs);
    ctx_menu_.addSeparator();
    ctx_menu_.addAction(ui->actionRoundTripTime);
    ctx_menu_.addAction(ui->actionThroughput);
    ctx_menu_.addAction(ui->actionStevens);
    ctx_menu_.addAction(ui->actionTcptrace);
    ctx_menu_.addAction(ui->actionWindowScaling);

    memset (&graph_, 0, sizeof(graph_));
    graph_.type = graph_type;
    copy_address(&graph_.src_address, &current.ip_src);
    graph_.src_port = current.th_sport;
    copy_address(&graph_.dst_address, &current.ip_dst);
    graph_.dst_port = current.th_dport;
    graph_.stream = header->th_stream;
    findStream();

    showWidgetsForGraphType();

    /* ui->streamNumberSpinBox->blockSignals(true); */
    ui->streamNumberSpinBox->setMaximum(get_mptcp_stream_count() - 1);
    /* ui->streamNumberSpinBox->setValue(graph_.stream); */
    /* ui->streamNumberSpinBox->blockSignals(false); */

/* #ifdef MA_1_SECOND */
/*     ui->maWindowSizeSpinBox->blockSignals(true); */
/*     ui->maWindowSizeSpinBox->setDecimals(6); */
/*     ui->maWindowSizeSpinBox->setMinimum(0.000001); */
/*     ui->maWindowSizeSpinBox->setValue(ma_window_size_); */
/*     ui->maWindowSizeSpinBox->blockSignals(false); */
/* #endif */

/*     // set which Throughput graphs are displayed by default */
/*     ui->showSegLengthCheckBox->blockSignals(true); */
/*     ui->showSegLengthCheckBox->setChecked(true); */
/*     ui->showSegLengthCheckBox->blockSignals(false); */

/*     ui->showThroughputCheckBox->blockSignals(true); */
/*     ui->showThroughputCheckBox->setChecked(true); */
/*     ui->showThroughputCheckBox->blockSignals(false); */

/*     // set which WScale graphs are displayed by default */
/*     ui->showRcvWinCheckBox->blockSignals(true); */
/*     ui->showRcvWinCheckBox->setChecked(true); */
/*     ui->showRcvWinCheckBox->blockSignals(false); */

/*     ui->showBytesOutCheckBox->blockSignals(true); */
/*     ui->showBytesOutCheckBox->setChecked(true); */
/*     ui->showBytesOutCheckBox->blockSignals(false); */

    QCustomPlot *sp = ui->streamPlot;
/*     QCPPlotTitle *file_title = new QCPPlotTitle(sp, cf_get_display_name(cap_file_)); */
/*     file_title->setFont(sp->xAxis->labelFont()); */
/*     title_ = new QCPPlotTitle(sp); */
/*     sp->plotLayout()->insertRow(0); */
/*     sp->plotLayout()->addElement(0, 0, file_title); */
/*     sp->plotLayout()->insertRow(0); */
/*     sp->plotLayout()->addElement(0, 0, title_); */

/*     // Base Graph - enables selecting segments (both data and SACKs) */
/*     base_graph_ = sp->addGraph(); */
/*     base_graph_->setPen(QPen(QBrush(graph_color_1), 0.25)); */
/*     // Throughput Graph - rate of sent bytes */
/*     tput_graph_ = sp->addGraph(sp->xAxis, sp->yAxis2); */
/*     tput_graph_->setPen(QPen(QBrush(graph_color_2), 0.5)); */
/*     tput_graph_->setLineStyle(QCPGraph::lsStepLeft); */
/*     // Goodput Graph - rate of ACKed bytes */
/*     goodput_graph_ = sp->addGraph(sp->xAxis, sp->yAxis2); */
/*     goodput_graph_->setPen(QPen(QBrush(graph_color_3), 0.5)); */
/*     goodput_graph_->setLineStyle(QCPGraph::lsStepLeft); */
/*     // Seg Graph - displays forward data segments on tcptrace graph */
/*     seg_graph_ = sp->addGraph(); */
/*     seg_graph_->setErrorType(QCPGraph::etValue); */
/*     seg_graph_->setLineStyle(QCPGraph::lsNone); */
/*     seg_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDot, Qt::transparent, 0)); */
/*     seg_graph_->setErrorPen(QPen(QBrush(graph_color_1), 0.5)); */
/*     seg_graph_->setErrorBarSkipSymbol(false); // draw error spine as single line */
/*     seg_graph_->setErrorBarSize(pkt_point_size_); */
/*     // Ack Graph - displays ack numbers from reverse packets */
/*     ack_graph_ = sp->addGraph(); */
/*     ack_graph_->setPen(QPen(QBrush(graph_color_2), 0.5)); */
/*     ack_graph_->setLineStyle(QCPGraph::lsStepLeft); */
/*     // Sack Graph - displays highest number (most recent) SACK block */
/*     sack_graph_ = sp->addGraph(); */
/*     sack_graph_->setErrorType(QCPGraph::etValue); */
/*     sack_graph_->setLineStyle(QCPGraph::lsNone); */
/*     sack_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDot, Qt::transparent, 0)); */
/*     sack_graph_->setErrorPen(QPen(QBrush(graph_color_4), 0.5)); */
/*     sack_graph_->setErrorBarSkipSymbol(false); */
/*     sack_graph_->setErrorBarSize(0.0); */
/*     // Sack Graph 2 - displays subsequent SACK blocks */
/*     sack2_graph_ = sp->addGraph(); */
/*     sack2_graph_->setErrorType(QCPGraph::etValue); */
/*     sack2_graph_->setLineStyle(QCPGraph::lsNone); */
/*     sack2_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDot, Qt::transparent, 0)); */
/*     sack2_graph_->setErrorPen(QPen(QBrush(graph_color_5), 0.5)); */
/*     sack2_graph_->setErrorBarSkipSymbol(false); */
/*     sack2_graph_->setErrorBarSize(0.0); */
/*     // RWin graph - displays upper extent of RWIN advertised on reverse packets */
/*     rwin_graph_ = sp->addGraph(); */
/*     rwin_graph_->setPen(QPen(QBrush(graph_color_3), 0.5)); */
/*     rwin_graph_->setLineStyle(QCPGraph::lsStepLeft); */

/*     tracer_ = new QCPItemTracer(sp); */
/*     sp->addItem(tracer_); */

    // Triggers fillGraph() [ UNLESS the index is already graph_idx!! ]
    if (graph_idx != ui->graphTypeComboBox->currentIndex()) {
        // changing the current index will call fillGraph
        ui->graphTypeComboBox->setCurrentIndex(graph_idx);
    } else {
        // the current index is what we want - so fillGraph() manually
        fillGraph();
    }

    sp->setMouseTracking(true);

    sp->yAxis->setLabelColor(QColor(graph_color_1));
    sp->yAxis->setTickLabelColor(QColor(graph_color_1));

    tracer_->setVisible(false);
    toggleTracerStyle(true);

    QPushButton *save_bt = ui->buttonBox->button(QDialogButtonBox::Save);
    save_bt->setText(tr("Save As" UTF8_HORIZONTAL_ELLIPSIS));

    QPushButton *close_bt = ui->buttonBox->button(QDialogButtonBox::Close);
    if (close_bt) {
        close_bt->setDefault(true);
    }

    ProgressFrame::addToButtonBox(ui->buttonBox, parent);

    connect(sp, SIGNAL(mousePress(QMouseEvent*)), this, SLOT(graphClicked(QMouseEvent*)));
    connect(sp, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
    connect(sp, SIGNAL(mouseRelease(QMouseEvent*)), this, SLOT(mouseReleased(QMouseEvent*)));
    /* connect(sp, SIGNAL(axisClick(QCPAxis*,QCPAxis::SelectablePart,QMouseEvent*)), */
    /*         this, SLOT(axisClicked(QCPAxis*,QCPAxis::SelectablePart,QMouseEvent*))); */
    /* connect(sp->yAxis, SIGNAL(rangeChanged(QCPRange)), this, SLOT(transformYRange(QCPRange))); */
    disconnect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
    this->setResult(QDialog::Accepted);
}

MPTCPStreamDialog::~MPTCPStreamDialog()
{
    delete ui;
}


/* TODO
 *
 *
 **/
void MPTCPStreamDialog::fillGraph(bool reset_axes, bool set_focus)
{
    QCustomPlot *sp = ui->streamPlot;

    if (sp->graphCount() < 1) return;

    base_graph_->setLineStyle(QCPGraph::lsNone);
    tracer_->setGraph(NULL);

    // base_graph_ is always visible.
    for (int i = 0; i < sp->graphCount(); i++) {
        sp->graph(i)->clearData();
        sp->graph(i)->setVisible(i == 0 ? true : false);
    }

    base_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc, pkt_point_size_));

    sp->xAxis->setLabel(time_s_label_);
    sp->xAxis->setNumberFormat("gb");
    // Use enough precision to mark microseconds
    //    when zooming in on a <100s capture
    sp->xAxis->setNumberPrecision(8);
    sp->yAxis->setNumberFormat("f");
    sp->yAxis->setNumberPrecision(0);
    sp->yAxis2->setVisible(false);
    sp->yAxis2->setLabel(QString());

    if (!cap_file_) {
        QString dlg_title = QString(tr("No Capture Data"));
        setWindowTitle(dlg_title);
        title_->setText(dlg_title);
        sp->setEnabled(false);
        sp->yAxis->setLabel(QString());
        sp->replot();
        return;
    }

    ts_offset_ = 0;
    seq_offset_ = 0;
    bool first = true;
    guint64 bytes_fwd = 0;
    guint64 bytes_rev = 0;
    int pkts_fwd = 0;
    int pkts_rev = 0;

    time_stamp_map_.clear();
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        // NOTE - adding both forward and reverse packets to time_stamp_map_
        //   so that both data and acks are selectable
        //   (this is important especially in selecting particular SACK pkts)
        bool insert = true;
        if (!compareHeaders(seg)) {
            bytes_rev += seg->th_seglen;
            pkts_rev++;
            // only insert reverse packets if SACK present
            insert = (seg->num_sack_ranges != 0);
        } else {
            bytes_fwd += seg->th_seglen;
            pkts_fwd++;
        }
        double ts = seg->rel_secs + seg->rel_usecs / 1000000.0;
        if (first) {
            if (ts_origin_conn_) ts_offset_ = ts;
            if (seq_origin_zero_) {
                if (compareHeaders(seg))
                    seq_offset_ = seg->th_seq;
                else
                    seq_offset_ = seg->th_ack;
            }
            first = false;
        }
        if (insert) {
            time_stamp_map_.insertMulti(ts - ts_offset_, seg);
        }
    }

    switch (graph_.type) {
    /* case GRAPH_TSEQ_STEVENS: */
    /*     fillStevens(); */
    /*     break; */
    /* case GRAPH_TSEQ_TCPTRACE: */
    /*     fillTcptrace(); */
    /*     break; */
    case GRAPH_THROUGHPUT:
        fillThroughput();
        break;
    /* case GRAPH_RTT: */
    /*     fillRoundTripTime(); */
    /*     break; */
    /* case GRAPH_WSCALE: */
    /*     fillWindowScale(); */
    /*     break; */
    default:
        break;
    }
    sp->setEnabled(true);

    stream_desc_ = tr("%1 %2 pkts, %3 %4 %5 pkts, %6 ")
            .arg(UTF8_RIGHTWARDS_ARROW)
            .arg(gchar_free_to_qstring(format_size(pkts_fwd, format_size_unit_none|format_size_prefix_si)))
            .arg(gchar_free_to_qstring(format_size(bytes_fwd, format_size_unit_bytes|format_size_prefix_si)))
            .arg(UTF8_LEFTWARDS_ARROW)
            .arg(gchar_free_to_qstring(format_size(pkts_rev, format_size_unit_none|format_size_prefix_si)))
            .arg(gchar_free_to_qstring(format_size(bytes_rev, format_size_unit_bytes|format_size_prefix_si)));
    mouseMoved(NULL);
    if (reset_axes) {
        resetAxes();
    } else {
        sp->replot();
    }
    // Throughput and Window Scale graphs can hide base_graph_
    if (base_graph_ && base_graph_->visible())
        tracer_->setGraph(base_graph_);

    // XXX QCustomPlot doesn't seem to draw any sort of focus indicator.
    if (set_focus)
        sp->setFocus();
}


void MPTCPStreamDialog::fillThroughput()
{
    /**
     * TODO get throughput of TCP streams
     *
     * */
    QString dlg_title = QString(tr("Throughput")) + streamDescription();
#ifdef MA_1_SECOND
    dlg_title.append(tr(" (MA)"));
#else
    dlg_title.append(QString(tr(" (%1 Segment MA)")).arg(moving_avg_period_));
#endif
    setWindowTitle(dlg_title);
    title_->setText(dlg_title);

    QCustomPlot *sp = ui->streamPlot;
    sp->yAxis->setLabel(segment_length_label_);
    sp->yAxis2->setLabel(average_throughput_label_);
    sp->yAxis2->setLabelColor(QColor(graph_color_2));
    sp->yAxis2->setTickLabelColor(QColor(graph_color_2));
    sp->yAxis2->setVisible(true);

    base_graph_->setVisible(ui->showSegLengthCheckBox->isChecked());
    tput_graph_->setVisible(ui->showThroughputCheckBox->isChecked());
    goodput_graph_->setVisible(ui->showGoodputCheckBox->isChecked());

#ifdef MA_1_SECOND
    if (!graph_.segments) {
#else
    if (!graph_.segments || !graph_.segments->next) {
#endif
        dlg_title.append(tr(" [not enough data]"));
        return;
    }

    QVector<double> seg_rel_times, ack_rel_times;
    QVector<double> seg_lens, ack_lens;
    QVector<double> tput_times, gput_times;
    QVector<double> tputs, gputs;
    int oldest_seg = 0, oldest_ack = 0;
    guint64 seg_sum = 0, ack_sum = 0;
    guint32 seglen = 0;

#ifdef USE_SACKS_IN_GOODPUT_CALC
    // to incorporate SACKED segments into goodput calculation,
    //   need to keep track of all the SACK blocks we haven't yet
    //   fully ACKed.
    sack_list_t old_sacks, new_sacks;
    new_sacks.reserve(MAX_TCP_SACK_RANGES);
    // statically allocate current_sacks vector
    //   [ std::array might be better, but that is C++11 ]
    for (int i = 0; i < MAX_TCP_SACK_RANGES; ++i) {
        new_sacks.push_back(sack_t(0,0));
    }
    old_sacks.reserve(2*MAX_TCP_SACK_RANGES);
#endif // USE_SACKS_IN_GOODPUT_CALC

    // need first acked sequence number to jump-start
    //    computation of acked bytes per packet
    guint32 last_ack = 0;
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        // first reverse packet with ACK flag tells us first acked sequence #
        if (!compareHeaders(seg) && (seg->th_flags & TH_ACK)) {
            last_ack = seg->th_ack;
            break;
        }
    }
    // Financial charts don't show MA data until a full period has elapsed.
    //  [ NOTE - this is because they assume that there's old data that they
    //      don't have access to - but in our case we know that there's NO
    //      data prior to the first packet in the stream - so it's fine to
    //      spit out the MA immediately... ]
    // The Rosetta Code MA examples start spitting out values immediately.
    // For now use not-really-correct initial values just to keep our vector
    // lengths the same.
#ifdef MA_1_SECOND
    // NOTE that for the time-based MA case, you certainly can start with the
    //  first segment!
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
#else
    for (struct segment *seg = graph_.segments->next; seg != NULL; seg = seg->next) {
#endif
        bool is_forward_seg = compareHeaders(seg);
        QVector<double>& r_pkt_times = is_forward_seg ? seg_rel_times : ack_rel_times;
        QVector<double>& r_lens = is_forward_seg ? seg_lens : ack_lens;
        QVector<double>& r_Xput_times = is_forward_seg ? tput_times : gput_times;
        QVector<double>& r_Xputs = is_forward_seg ? tputs : gputs;
        int& r_oldest = is_forward_seg ? oldest_seg : oldest_ack;
        guint64& r_sum = is_forward_seg ? seg_sum : ack_sum;

        double ts = (seg->rel_secs + seg->rel_usecs / 1000000.0) - ts_offset_;

        if (is_forward_seg) {
            seglen = seg->th_seglen;
        } else {
            if ((seg->th_flags & TH_ACK) &&
                tcp_seq_eq_or_after(seg->th_ack, last_ack)) {
                seglen = seg->th_ack - last_ack;
                last_ack = seg->th_ack;
#ifdef USE_SACKS_IN_GOODPUT_CALC
                // copy any sack_ranges into new_sacks, and sort.
                for(int i = 0; i < seg->num_sack_ranges; ++i) {
                    new_sacks[i].first = seg->sack_left_edge[i];
                    new_sacks[i].second = seg->sack_right_edge[i];
                }
                std::sort(new_sacks.begin(),
                          new_sacks.begin() + seg->num_sack_ranges,
                          compare_sack);

                // adjust the seglen based on new and old sacks,
                //   and update the old_sacks list
                goodput_adjust_for_sacks(&seglen, last_ack,
                                         new_sacks, seg->num_sack_ranges,
                                         old_sacks);
#endif // USE_SACKS_IN_GOODPUT_CALC
            } else {
                seglen = 0;
            }
        }

        r_pkt_times.append(ts);
        r_lens.append(seglen);

#ifdef MA_1_SECOND
        while (r_oldest < r_pkt_times.size() && ts - r_pkt_times[r_oldest] > ma_window_size_) {
            r_sum -= r_lens[r_oldest];
            // append points where a packet LEAVES the MA window
            //   (as well as, below, where they ENTER the MA window)
            r_Xputs.append(r_sum * 8.0 / ma_window_size_);
            r_Xput_times.append(r_pkt_times[r_oldest] + ma_window_size_);
            r_oldest++;
        }
#else
        if (r_lens.size() > moving_avg_period_) {
            r_sum -= r_lens[r_oldest];
            r_oldest++;
        }
#endif

        // av_Xput computes Xput, i.e.:
        //    throughput for forward packets
        //    goodput for reverse packets
        double av_Xput;
        r_sum += seglen;
#ifdef MA_1_SECOND
        // for time-based MA, delta_t is constant
        av_Xput = r_sum * 8.0 / ma_window_size_;
#else
        double dtime = 0.0;
        if (r_oldest > 0)
            dtime = ts - r_pkt_times[r_oldest-1];
        if (dtime > 0.0) {
            av_Xput = r_sum * 8.0 / dtime;
        } else {
            av_Xput = 0.0;
        }
#endif

        // Add a data point only if our time window has advanced. Otherwise
        // update the most recent point. (We might want to show a warning
        // for out-of-order packets.)
        if (r_Xput_times.size() > 0 && ts <= r_Xput_times.last()) {
            r_Xputs[r_Xputs.size() - 1] = av_Xput;
        } else {
            r_Xputs.append(av_Xput);
            r_Xput_times.append(ts);
        }
    }
    base_graph_->setData(seg_rel_times, seg_lens);
    tput_graph_->setData(tput_times, tputs);
    goodput_graph_->setData(gput_times, gputs);
}

