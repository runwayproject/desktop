#include "chatview.h"

#include <QListWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QDateTime>
#include <QObject>

ChatView::ChatView(QWidget *parent)
    : QWidget(parent)
    , m_messages(new QListWidget(this))
    , m_input(new QLineEdit(this))
    , m_sendButton(new QPushButton(tr("Send"), this))
{
    m_input->setPlaceholderText(tr("Type a message..."));

    auto *inputLayout = new QHBoxLayout;
    inputLayout->setContentsMargins(0, 0, 0, 0);
    inputLayout->addWidget(m_input);
    inputLayout->addWidget(m_sendButton);

    auto *mainLayout = new QVBoxLayout(this);
    mainLayout->addWidget(m_messages);
    mainLayout->addLayout(inputLayout);
    setLayout(mainLayout);

    connect(m_sendButton, &QPushButton::clicked, this, &ChatView::sendMessage);
    connect(m_input, &QLineEdit::returnPressed, this, &ChatView::sendMessage);
}

ChatView::~ChatView() = default;

void ChatView::sendMessage()
{
    const QString text = m_input->text().trimmed();
    if (text.isEmpty())
        return;

    const QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    m_messages->addItem(QString("[%1] %2").arg(timestamp, text));
    m_messages->scrollToBottom();
    m_input->clear();
}

ChatView* ChatView::showWindow(QWidget* parent)
{
    ChatView* w = new ChatView(parent);
    if (!parent) {
        w->setAttribute(Qt::WA_DeleteOnClose);
    }
    w->setWindowTitle(QObject::tr("Chat"));
    w->show();
    return w;
}
