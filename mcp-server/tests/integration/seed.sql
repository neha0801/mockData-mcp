/*
  Integration fixture. Every literal and every row holds a CANARY value that must
  never appear in any tool output. Batches are separated by GO lines.
*/
IF DB_ID(N'MockdataIT') IS NOT NULL
BEGIN
    ALTER DATABASE MockdataIT SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE MockdataIT;
END
GO
CREATE DATABASE MockdataIT;
GO
USE MockdataIT;
GO
CREATE SCHEMA app;
GO
CREATE SCHEMA secret;
GO
CREATE TABLE app.Clients (
    ClientId int IDENTITY CONSTRAINT PK_Clients PRIMARY KEY,
    Lei char(20) NOT NULL CONSTRAINT UQ_Clients_Lei UNIQUE,
    FullName nvarchar(200) NOT NULL,
    Email varchar(254) NULL
);
CREATE TABLE app.Accounts (
    AccountId int IDENTITY CONSTRAINT PK_Accounts PRIMARY KEY,
    ClientId int NOT NULL CONSTRAINT FK_Accounts_Clients REFERENCES app.Clients (ClientId),
    AccountNo varchar(34) NOT NULL CONSTRAINT DF_Accounts_No DEFAULT ('CANARY-DEFAULT-55443322'),
    Status char(1) NOT NULL CONSTRAINT CK_Accounts_Status CHECK (Status IN ('O', 'C')),
    Balance decimal(18, 2) NOT NULL CONSTRAINT DF_Accounts_Balance DEFAULT (99887766),
    CreditLimit AS (Balance * 1.5),
    CONSTRAINT CK_Accounts_NotBlocked CHECK (AccountNo <> 'GB33BUKB20201555555555')
);
CREATE INDEX IX_Accounts_No ON app.Accounts (AccountNo) INCLUDE (Status) WHERE AccountNo <> 'CANARY-FILTER-11223344';
CREATE TABLE secret.Keys (KeyId int CONSTRAINT PK_Keys PRIMARY KEY, KeyValue varbinary(64) NULL);

INSERT app.Clients (Lei, FullName, Email) VALUES ('5493001KJTIIGC8Y1R12', N'Jane Canary', 'canary.person@example.com');
INSERT app.Accounts (ClientId, AccountNo, Status, Balance) VALUES (1, 'GB82WEST12345698765432', 'O', 99887766.00);
INSERT secret.Keys (KeyId, KeyValue) VALUES (1, 0x4111111111111111);
GO
CREATE VIEW app.vBigAccounts AS
    SELECT AccountId, AccountNo FROM app.Accounts WHERE Balance > 250000 AND AccountNo <> 'CANARY-VIEW-66778899';
GO
CREATE PROCEDURE app.usp_Route @Client nvarchar(50), @Amount decimal(18, 2) AS
BEGIN
    -- hard-coded for Jane Canary, canary.person@example.com
    /* acct 99887766 */
    IF @Client = N'CANARY-PROC-99887766' SELECT 'ROUTE_A' AS route;
    ELSE IF @Client = '5493001KJTIIGC8Y1R12'
        SELECT AccountId FROM app.Accounts WHERE AccountNo = 'GB82WEST12345698765432' AND Balance > @Amount;
END
GO
CREATE FUNCTION app.fn_Fee (@Amount decimal(18, 2)) RETURNS decimal(18, 2) AS
BEGIN
    RETURN CASE WHEN @Amount > 99887766 THEN 0 ELSE 12.5 END;
END
GO
CREATE PROCEDURE app.usp_Encrypted WITH ENCRYPTION AS SELECT 'CANARY-ENC-12121212' AS x;
GO
CREATE TRIGGER app.trg_Accounts ON app.Accounts AFTER INSERT AS
BEGIN
    IF EXISTS (SELECT 1 FROM inserted WHERE AccountNo = 'CANARY-TRG-34343434') ROLLBACK;
END
GO
