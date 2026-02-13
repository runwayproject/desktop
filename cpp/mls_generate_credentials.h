#pragma once

#include <QDialog>

class QLabel;
class QPushButton;

class MlsGenerateCredentialsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit MlsGenerateCredentialsDialog(QWidget* parent = nullptr);
    ~MlsGenerateCredentialsDialog() override = default;

    static bool askToCreate(QWidget* parent = nullptr);

private slots:
    void onYesClicked();

private:
    void createCredentialsRequested();

    QLabel* m_messageLabel;
    QPushButton* m_yesButton;
    QPushButton* m_noButton;
};