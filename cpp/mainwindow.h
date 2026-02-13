#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

class ChatView;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    ChatView *m_chatView;
};

#endif // MAINWINDOW_H
