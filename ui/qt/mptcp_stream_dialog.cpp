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

#include "tcp_stream_dialog.h"
#include <ui_tcp_stream_dialog.h>

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
    QDialog(NULL, Qt::Window),
    ui(new Ui::MPTCPStreamDialog),
    cap_file_(cf),
    ts_offset_(0),
    ts_origin_conn_(true),
    seq_offset_(0),
    seq_origin_zero_(true),
    title_(NULL),
    base_graph_(NULL),
    tput_graph_(NULL),
    goodput_graph_(NULL),
    seg_graph_(NULL),
    ack_graph_(NULL),
    sack_graph_(NULL),
    sack2_graph_(NULL),
    rwin_graph_(NULL),
    tracer_(NULL),
    packet_num_(0),
    mouse_drags_(true),
    rubber_band_(NULL),
    graph_updater_(this),
    num_dsegs_(-1),
    num_acks_(-1),
    num_sack_ranges_(-1),
    ma_window_size_(1.0)
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

    ui->streamNumberSpinBox->blockSignals(true);
    ui->streamNumberSpinBox->setMaximum(get_tcp_stream_count() - 1);
    ui->streamNumberSpinBox->setValue(graph_.stream);
    ui->streamNumberSpinBox->blockSignals(false);

#ifdef MA_1_SECOND
    ui->maWindowSizeSpinBox->blockSignals(true);
    ui->maWindowSizeSpinBox->setDecimals(6);
    ui->maWindowSizeSpinBox->setMinimum(0.000001);
    ui->maWindowSizeSpinBox->setValue(ma_window_size_);
    ui->maWindowSizeSpinBox->blockSignals(false);
#endif

    // set which Throughput graphs are displayed by default
    ui->showSegLengthCheckBox->blockSignals(true);
    ui->showSegLengthCheckBox->setChecked(true);
    ui->showSegLengthCheckBox->blockSignals(false);

    ui->showThroughputCheckBox->blockSignals(true);
    ui->showThroughputCheckBox->setChecked(true);
    ui->showThroughputCheckBox->blockSignals(false);

    // set which WScale graphs are displayed by default
    ui->showRcvWinCheckBox->blockSignals(true);
    ui->showRcvWinCheckBox->setChecked(true);
    ui->showRcvWinCheckBox->blockSignals(false);

    ui->showBytesOutCheckBox->blockSignals(true);
    ui->showBytesOutCheckBox->setChecked(true);
    ui->showBytesOutCheckBox->blockSignals(false);

    QCustomPlot *sp = ui->streamPlot;
    QCPPlotTitle *file_title = new QCPPlotTitle(sp, cf_get_display_name(cap_file_));
    file_title->setFont(sp->xAxis->labelFont());
    title_ = new QCPPlotTitle(sp);
    sp->plotLayout()->insertRow(0);
    sp->plotLayout()->addElement(0, 0, file_title);
    sp->plotLayout()->insertRow(0);
    sp->plotLayout()->addElement(0, 0, title_);

    // Base Graph - enables selecting segments (both data and SACKs)
    base_graph_ = sp->addGraph();
    base_graph_->setPen(QPen(QBrush(graph_color_1), 0.25));
    // Throughput Graph - rate of sent bytes
    tput_graph_ = sp->addGraph(sp->xAxis, sp->yAxis2);
    tput_graph_->setPen(QPen(QBrush(graph_color_2), 0.5));
    tput_graph_->setLineStyle(QCPGraph::lsStepLeft);
    // Goodput Graph - rate of ACKed bytes
    goodput_graph_ = sp->addGraph(sp->xAxis, sp->yAxis2);
    goodput_graph_->setPen(QPen(QBrush(graph_color_3), 0.5));
    goodput_graph_->setLineStyle(QCPGraph::lsStepLeft);
    // Seg Graph - displays forward data segments on tcptrace graph
    seg_graph_ = sp->addGraph();
    seg_graph_->setErrorType(QCPGraph::etValue);
    seg_graph_->setLineStyle(QCPGraph::lsNone);
    seg_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDot, Qt::transparent, 0));
    seg_graph_->setErrorPen(QPen(QBrush(graph_color_1), 0.5));
    seg_graph_->setErrorBarSkipSymbol(false); // draw error spine as single line
    seg_graph_->setErrorBarSize(pkt_point_size_);
    // Ack Graph - displays ack numbers from reverse packets
    ack_graph_ = sp->addGraph();
    ack_graph_->setPen(QPen(QBrush(graph_color_2), 0.5));
    ack_graph_->setLineStyle(QCPGraph::lsStepLeft);
    // Sack Graph - displays highest number (most recent) SACK block
    sack_graph_ = sp->addGraph();
    sack_graph_->setErrorType(QCPGraph::etValue);
    sack_graph_->setLineStyle(QCPGraph::lsNone);
    sack_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDot, Qt::transparent, 0));
    sack_graph_->setErrorPen(QPen(QBrush(graph_color_4), 0.5));
    sack_graph_->setErrorBarSkipSymbol(false);
    sack_graph_->setErrorBarSize(0.0);
    // Sack Graph 2 - displays subsequent SACK blocks
    sack2_graph_ = sp->addGraph();
    sack2_graph_->setErrorType(QCPGraph::etValue);
    sack2_graph_->setLineStyle(QCPGraph::lsNone);
    sack2_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDot, Qt::transparent, 0));
    sack2_graph_->setErrorPen(QPen(QBrush(graph_color_5), 0.5));
    sack2_graph_->setErrorBarSkipSymbol(false);
    sack2_graph_->setErrorBarSize(0.0);
    // RWin graph - displays upper extent of RWIN advertised on reverse packets
    rwin_graph_ = sp->addGraph();
    rwin_graph_->setPen(QPen(QBrush(graph_color_3), 0.5));
    rwin_graph_->setLineStyle(QCPGraph::lsStepLeft);

    tracer_ = new QCPItemTracer(sp);
    sp->addItem(tracer_);

    // Triggers fillGraph() [ UNLESS the index is already graph_idx!! ]
    if (graph_idx != ui->graphTypeComboBox->currentIndex())
        // changing the current index will call fillGraph
        ui->graphTypeComboBox->setCurrentIndex(graph_idx);
    else
        // the current index is what we want - so fillGraph() manually
        fillGraph();

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
    connect(sp, SIGNAL(axisClick(QCPAxis*,QCPAxis::SelectablePart,QMouseEvent*)),
            this, SLOT(axisClicked(QCPAxis*,QCPAxis::SelectablePart,QMouseEvent*)));
    connect(sp->yAxis, SIGNAL(rangeChanged(QCPRange)), this, SLOT(transformYRange(QCPRange)));
    disconnect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
    this->setResult(QDialog::Accepted);
}

MPTCPStreamDialog::~MPTCPStreamDialog()
{
    delete ui;
}

