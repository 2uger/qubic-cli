#pragma once

#include "structs.h"

constexpr uint64_t QLOAN_MAX_ASSETS_NUM = 2;
constexpr uint64_t QLOAN_MAX_OUTPUT_NUM = 128;

struct Asset
{
    uint8_t assetIssuer[32];
    uint64_t assetName;
};

struct placeLoanReq_input
{
    uint8_t privateId[32];

    Asset assets[QLOAN_MAX_ASSETS_NUM];
    int64_t assetAmount[QLOAN_MAX_ASSETS_NUM];
    uint8_t assetsNum;

    uint64_t price;
    uint64_t interestRate;
    uint64_t loanReturnPeriodInEpochs;

    bool isLoanReq;
    bool assetsToCreditor;
};

struct placeLoanReq_output {};

struct acceptLoanReq_input
{
    uint64_t reqId;
};

struct acceptLoanReq_output {};

struct getAllLoanReqs_input {};

enum class LoanReqState : uint8_t
{
    IDLE = 1,
    ACTIVE,
    PAYED,
    EXPIRED,
};

struct LoanReq
{
    uint8_t borrowerId[32];
    uint8_t creditorId[32];
    uint8_t acceptedById[32];
    uint8_t privateId[32];

    uint64_t reqId;

    Asset assets[QLOAN_MAX_ASSETS_NUM];
    int64_t assetAmount[QLOAN_MAX_ASSETS_NUM];
    uint8_t assetsNum;

    uint64_t priceAmount;
    uint64_t interestRate;
    uint64_t debtAmount;

    uint64_t returnPeriodInEpochs;
    uint64_t epochsLeft;

    enum LoanReqState state;
};

struct getAllLoanReqs_output
{
    LoanReq loanReqs[QLOAN_MAX_OUTPUT_NUM];
    uint64_t loanReqsAmount;

    static constexpr unsigned char type() {
        return RespondContractFunction::type();
    }
};

struct getUserActiveLoanReqs_input
{
    uint8_t userId[32];
};

struct getUserActiveLoanReqs_output
{
    LoanReq loanReqs[QLOAN_MAX_OUTPUT_NUM];
    uint64_t loanReqsAmount;

    static constexpr unsigned char type() {
        return RespondContractFunction::type();
    }
};

struct getUserAcceptedLoanReqs_input
{
    uint8_t userId[32];
};

struct getUserAcceptedLoanReqs_output
{
    LoanReq loanReqs[QLOAN_MAX_OUTPUT_NUM];
    uint64_t loanReqsAmount;

    static constexpr unsigned char type() {
        return RespondContractFunction::type();
    }
};

struct getFeesInfo_input {};

struct getFeesInfo_output
{
    uint64_t acceptanceFeePercent;
    uint64_t distributeFeePercent;
    uint64_t burnFeePercent;

    uint64_t earnedAmount;
    uint64_t distributedAmount;
    uint64_t burnedAmount;
    uint64_t toDevsAmount;

    static constexpr unsigned char type() {
        return RespondContractFunction::type();
    }
};

struct getUserDebt_input
{
    uint8_t userId[32];
};

struct getUserDebt_output
{
    uint64_t totalUserDebt;

    static constexpr unsigned char type() {
        return RespondContractFunction::type();
    }
};

struct removeLoanRequest_input
{
    uint64_t reqId;
};

struct removeLoanRequest_output {};

struct releaseAsset_input
{
    uint8_t assetIssuer[32];
    uint64_t assetName;
    uint64_t toReleaseAmount;
    uint16_t dstManagingContractIdx;
};

struct releaseAsset_output {};

struct payLoanDebt_input
{
    uint64_t reqId;
};

struct payLoanDebt_output {};

void qloanPlaceLoanReq(const char* nodeIp, int nodePort,
                       const char* seed,
                       char* assetIssuer[QLOAN_MAX_ASSETS_NUM],
                       char* assetName[QLOAN_MAX_ASSETS_NUM],
                       const uint64_t loanAssetAmount[QLOAN_MAX_ASSETS_NUM],
                       const char* privateId,
                       bool isRequest,
                       const uint8_t assetsNum,
                       const uint64_t loanPrice,
                       const uint64_t loanInterestRate,
                       const uint64_t loanReturnPeriodInEpochs,
                       const uint32_t scheduledTickOffset,
                       bool assetsToCreditor);
void qloanAcceptLoanReq(const char* nodeIp, int nodePort,
                        const char* seed,
                        const uint64_t loanReqId,
                        const uint32_t scheduledTickOffset);
void qloanRemoveLoanReq(const char* nodeIp, int nodePort,
                        const char* seed,
                        const uint64_t loanReqId,
                        const uint32_t scheduledTickOffset);
void qloanReleaseAsset(const char* nodeIp, int nodePort,
                       const char* seed,
                       const char* assetIssuer,
                       const char* assetName,
                       const uint64_t toReleaseAmount,
                       const uint16_t dstManagingContractIdx,
                       const uint32_t scheduledTickOffset);
void qloanPayLoanDebt(const char* nodeIp, int nodePort,
                      const char* seed,
                      const uint64_t loanReqId,
                      const uint32_t scheduledTickOffset);

void qloanGetAllLoanReqs(const char* nodeIp, int nodePort);
void qloanGetUserActiveLoanReqs(const char* nodeIp, int nodePort, const char* userId);
void qloanGetUserAcceptedLoanReqs(const char* nodeIp, int nodePort, const char* userId);
void qloanGetFees(const char* nodeIp, int nodePort);
void qloanGetUserDebt(const char* nodeIp, int nodePort, const char* userId);

