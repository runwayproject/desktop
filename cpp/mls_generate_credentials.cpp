#include "mls_generate_credentials.h"

#include <QLabel>
#include <QPushButton>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <iostream>
#include "../rust/target/cxxbridge/asphalt/src/lib.rs.h"

MlsGenerateCredentialsDialog::MlsGenerateCredentialsDialog(QWidget* parent)
    : QDialog(parent)
    , m_messageLabel(new QLabel(this))
    , m_yesButton(new QPushButton(tr("Yes"), this))
    , m_noButton(new QPushButton(tr("No"), this))
{
    setWindowTitle(tr("MLS Credentials Missing"));

    m_messageLabel->setText(tr("MLS credentials were not found. Do you want to create them now?"));
    m_messageLabel->setWordWrap(true);

    connect(m_yesButton, &QPushButton::clicked, this, &MlsGenerateCredentialsDialog::onYesClicked);
    connect(m_noButton, &QPushButton::clicked, this, &QDialog::reject);

    auto* buttonLayout = new QHBoxLayout;
    buttonLayout->addStretch();
    buttonLayout->addWidget(m_yesButton);
    buttonLayout->addWidget(m_noButton);

    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->addWidget(m_messageLabel);
    mainLayout->addLayout(buttonLayout);

    setLayout(mainLayout);
    setModal(true);
    resize(420, 120);
}

bool MlsGenerateCredentialsDialog::askToCreate(QWidget* parent)
{
    MlsGenerateCredentialsDialog dlg(parent);
    return dlg.exec() == QDialog::Accepted;
}

void MlsGenerateCredentialsDialog::onYesClicked()
{
    createCredentialsRequested();
    accept();
}

void MlsGenerateCredentialsDialog::createCredentialsRequested()
{
    create_credentials_openmls();
}
