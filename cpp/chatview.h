#ifndef CHATVIEW_H
#define CHATVIEW_H

#include <QWidget>

class QListWidget;
class QLineEdit;
class QPushButton;

class ChatView : public QWidget
{
    Q_OBJECT

public:
    explicit ChatView(QWidget *parent = nullptr);
    ~ChatView();

    static ChatView* showWindow(QWidget* parent = nullptr);

private slots:
    void sendMessage();

private:
    QListWidget *m_messages;
    QLineEdit *m_input;
    QPushButton *m_sendButton;
};

#endif // CHATVIEW_H