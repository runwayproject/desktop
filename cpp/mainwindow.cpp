#include "mainwindow.h"
#include "chatview.h"
#include "mls_generate_credentials.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    const bool credentialsFound = false;

    if (!credentialsFound) {
        if (MlsGenerateCredentialsDialog::askToCreate(this)) {

        } else {
            
        }

        setWindowTitle(tr("Asphalt: MLS Credentials Missing"));
    } else {
        setWindowTitle(tr("Chat"));
    }

    setCentralWidget(m_chatView);
}

MainWindow::~MainWindow() {}