#include "qloan.h"
#include "structs.h"
#include "logger.h"
#include "connection.h"
#include "wallet_utils.h"
#include "node_utils.h"
#include "key_utils.h"
#include "k12_and_key_utils.h"

#include <algorithm>
#include <map>
#include <string>

#define QLOAN_CONTRACT_INDEX 18

#define QLOAN_PLACE_LOAN_REQ  1
#define QLOAN_REMOVE_LOAN_REQ 2
#define QLOAN_ACCEPT_LOAN_REQ 3
#define QLOAN_RELEASE_ASSET   4
#define QLOAN_PAY_DEBT        5

#define QLOAN_GET_ACTIVE_LOAN_REQS        1
#define QLOAN_GET_USER_ACTIVE_LOAN_REQS   2
#define QLOAN_GET_USER_ACCEPTED_LOAN_REQS 3
#define QLOAN_GET_FEES                    4
#define QLOAN_GET_USER_DEBT               5

const std::string NULL_ID = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFXIB";

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
                       bool assetsToCreditor)
{
    placeLoanReq_input input;

    memset(&input, 0, sizeof(input));
    printf("Sizeof: %ld\n", sizeof(placeLoanReq_input));
    for (unsigned int i = 0; i < assetsNum; i++)
    {
        // This function is important, because it's translate user ID from UPPER_CASE to lower_case
        getPublicKeyFromIdentity(assetIssuer[i], input.assets[i].assetIssuer);
        input.assets[i].assetName = 0;
        memcpy(&input.assets[i].assetName, assetName[i], strlen(assetName[i]));
        input.assetAmount[i] = loanAssetAmount[i];
        LOG("asset issuer: %0.32s, Asset name: %0.32s, amount: %ld\n", assetIssuer[i], assetName[i], loanAssetAmount[i]);
    }
    input.assetsNum = assetsNum;

    input.price = loanPrice;
    input.interestRate = loanInterestRate;
    input.loanReturnPeriodInEpochs = loanReturnPeriodInEpochs;
    LOG("Asset num: %d, price: %d, interest rate: %d, return period: %d, isRequest: %d\n", assetsNum, loanPrice, loanInterestRate, loanReturnPeriodInEpochs, isRequest);

    // Means no private id and load request is public
    getPublicKeyFromIdentity(privateId[0] == '0' ? NULL_ID.c_str() : privateId, input.privateId);

    input.isLoanReq = isRequest;
    input.assetsToCreditor = assetsToCreditor;

    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) {
        LOG("Failed to connect to node.\n");
        return;
    }

    uint8_t subseed[32] = { 0 };
    uint8_t privateKey[32] = { 0 };
    uint8_t sourcePublicKey[32] = { 0 };
    uint8_t destPublicKey[32] = { 0 };
    uint8_t digest[32];
    uint8_t signature[64];
    char publicIdentity[128] = { 0 };
    char txHash[128] = { 0 };
    const bool isLowerCase = false;

    //
    // Common part to getting all the keys(public, private) from seed
    //
    getSubseedFromSeed((uint8_t*) seed, subseed);
    getPrivateKeyFromSubSeed(subseed, privateKey);
    getPublicKeyFromPrivateKey(privateKey, sourcePublicKey);
    getIdentityFromPublicKey(sourcePublicKey, publicIdentity, isLowerCase);
    memset(destPublicKey, 0, 32);
    ((uint64_t*) destPublicKey)[0] = QLOAN_CONTRACT_INDEX;

    struct {
        RequestResponseHeader header;
        Transaction transaction;
        placeLoanReq_input inputData;
        uint8_t sig[64];
    } packet;

    //
    // Filling the transaction packet to send
    //
    memset(&packet, 0, sizeof(packet));
    memcpy(packet.transaction.sourcePublicKey, sourcePublicKey, 32);
    memcpy(packet.transaction.destinationPublicKey, destPublicKey, 32);
    packet.transaction.amount = 3000;
    uint32_t currentTick = getTickNumberFromNode(qc);
    packet.transaction.tick = currentTick + scheduledTickOffset;
    packet.transaction.inputType = QLOAN_PLACE_LOAN_REQ;
    packet.transaction.inputSize = sizeof(input);
    memcpy(&packet.inputData, &input, sizeof(input));

    //
    // Crypto magic to sign my transaction with private key, i guess
    //
    KangarooTwelve((uint8_t*)&packet.transaction,
                   sizeof(packet.transaction) + sizeof(input),
                   digest, 
                   32);
    sign(subseed, sourcePublicKey, digest, signature);
    memcpy(packet.sig, signature, 64);
    packet.header.setSize(sizeof(packet));
    packet.header.zeroDejavu();
    packet.header.setType(BROADCAST_TRANSACTION);

    //
    // Sending transaction itself
    //
    qc->sendData((uint8_t*)&packet, packet.header.size());

    KangarooTwelve((uint8_t*)&packet.transaction, 
                   sizeof(packet.transaction) + sizeof(input) + SIGNATURE_SIZE, 
                   digest,
                   32);
    getTxHashFromDigest(digest, txHash);
    printReceipt(packet.transaction, txHash, nullptr);
    LOG("\n%u\n", currentTick);
    LOG("run ./qubic-cli [...] -checktxontick %u %s\n", currentTick + scheduledTickOffset, txHash);
    LOG("to check your tx confirmation status\n");
}

void qloanAcceptLoanReq(const char* nodeIp, int nodePort,
                        const char* seed,
                        const uint64_t loanReqId,
                        const uint32_t scheduledTickOffset)
{
    acceptLoanReq_input input;
    input.reqId = loanReqId;

    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) {
        LOG("Failed to connect to node.\n");
        return;
    }

    uint8_t subseed[32] = { 0 };
    uint8_t privateKey[32] = { 0 };
    uint8_t sourcePublicKey[32] = { 0 };
    uint8_t destPublicKey[32] = { 0 };
    uint8_t digest[32];
    uint8_t signature[64];
    char publicIdentity[128] = { 0 };
    char txHash[128] = { 0 };
    const bool isLowerCase = false;

    //
    // Common part to getting all the keys(public, private) from seed
    //
    getSubseedFromSeed((uint8_t*) seed, subseed);
    getPrivateKeyFromSubSeed(subseed, privateKey);
    getPublicKeyFromPrivateKey(privateKey, sourcePublicKey);
    getIdentityFromPublicKey(sourcePublicKey, publicIdentity, isLowerCase);
    memset(destPublicKey, 0, 32);
    ((uint64_t*) destPublicKey)[0] = QLOAN_CONTRACT_INDEX;

    struct {
        RequestResponseHeader header;
        Transaction transaction;
        acceptLoanReq_input inputData;
        uint8_t sig[64];
    } packet;

    //
    // Filling the transaction packet to send
    //
    memset(&packet, 0, sizeof(packet));
    memcpy(packet.transaction.sourcePublicKey, sourcePublicKey, 32);
    memcpy(packet.transaction.destinationPublicKey, destPublicKey, 32);
    packet.transaction.amount = 1000;
    uint32_t currentTick = getTickNumberFromNode(qc);
    packet.transaction.tick = currentTick + scheduledTickOffset;
    packet.transaction.inputType = QLOAN_ACCEPT_LOAN_REQ;
    packet.transaction.inputSize = sizeof(input);
    memcpy(&packet.inputData, &input, sizeof(input));

    //
    // Crypto magic to sign my transaction with private key, i guess
    //
    KangarooTwelve((uint8_t*)&packet.transaction,
                   sizeof(packet.transaction) + sizeof(input),
                   digest, 
                   32);
    sign(subseed, sourcePublicKey, digest, signature);
    memcpy(packet.sig, signature, 64);
    packet.header.setSize(sizeof(packet));
    packet.header.zeroDejavu();
    packet.header.setType(BROADCAST_TRANSACTION);

    //
    // Sending transaction itself
    //
    qc->sendData((uint8_t*)&packet, packet.header.size());

    KangarooTwelve((uint8_t*)&packet.transaction, 
                   sizeof(packet.transaction) + sizeof(input) + SIGNATURE_SIZE, 
                   digest,
                   32);
    getTxHashFromDigest(digest, txHash);
    printReceipt(packet.transaction, txHash, nullptr);
    LOG("\n%u\n", currentTick);
    LOG("run ./qubic-cli [...] -checktxontick %u %s\n", currentTick + scheduledTickOffset, txHash);
    LOG("to check your tx confirmation status\n");
}

void qloanRemoveLoanReq(const char* nodeIp, int nodePort,
                        const char* seed,
                        const uint64_t loanReqId,
                        const uint32_t scheduledTickOffset)
{
    removeLoanRequest_input input;
    input.reqId = loanReqId;

    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) {
        LOG("Failed to connect to node.\n");
        return;
    }

    uint8_t subseed[32] = { 0 };
    uint8_t privateKey[32] = { 0 };
    uint8_t sourcePublicKey[32] = { 0 };
    uint8_t destPublicKey[32] = { 0 };
    uint8_t digest[32];
    uint8_t signature[64];
    char publicIdentity[128] = { 0 };
    char txHash[128] = { 0 };
    const bool isLowerCase = false;

    //
    // Common part to getting all the keys(public, private) from seed
    //
    getSubseedFromSeed((uint8_t*) seed, subseed);
    getPrivateKeyFromSubSeed(subseed, privateKey);
    getPublicKeyFromPrivateKey(privateKey, sourcePublicKey);
    getIdentityFromPublicKey(sourcePublicKey, publicIdentity, isLowerCase);
    memset(destPublicKey, 0, 32);
    ((uint64_t*) destPublicKey)[0] = QLOAN_CONTRACT_INDEX;

    struct {
        RequestResponseHeader header;
        Transaction transaction;
        removeLoanRequest_input inputData;
        uint8_t sig[64];
    } packet;

    //
    // Filling the transaction packet to send
    //
    memset(&packet, 0, sizeof(packet));
    memcpy(packet.transaction.sourcePublicKey, sourcePublicKey, 32);
    memcpy(packet.transaction.destinationPublicKey, destPublicKey, 32);
    packet.transaction.amount = 100;
    uint32_t currentTick = getTickNumberFromNode(qc);
    packet.transaction.tick = currentTick + scheduledTickOffset;
    packet.transaction.inputType = QLOAN_REMOVE_LOAN_REQ;
    packet.transaction.inputSize = sizeof(input);
    memcpy(&packet.inputData, &input, sizeof(input));

    //
    // Crypto magic to sign my transaction with private key, i guess
    //
    KangarooTwelve((uint8_t*)&packet.transaction,
                   sizeof(packet.transaction) + sizeof(input),
                   digest, 
                   32);
    sign(subseed, sourcePublicKey, digest, signature);
    memcpy(packet.sig, signature, 64);
    packet.header.setSize(sizeof(packet));
    packet.header.zeroDejavu();
    packet.header.setType(BROADCAST_TRANSACTION);

    //
    // Sending transaction itself
    //
    qc->sendData((uint8_t*)&packet, packet.header.size());

    KangarooTwelve((uint8_t*)&packet.transaction, 
                   sizeof(packet.transaction) + sizeof(input) + SIGNATURE_SIZE, 
                   digest,
                   32);
    getTxHashFromDigest(digest, txHash);
    printReceipt(packet.transaction, txHash, nullptr);
    LOG("\n%u\n", currentTick);
    LOG("run ./qubic-cli [...] -checktxontick %u %s\n", currentTick + scheduledTickOffset, txHash);
    LOG("to check your tx confirmation status\n");
}

void qloanPayLoanDebt(const char* nodeIp, int nodePort,
                      const char* seed,
                      const uint64_t loanReqId,
                      const uint32_t scheduledTickOffset)
{
    payLoanDebt_input input;
    input.reqId = loanReqId;

    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) {
        LOG("Failed to connect to node.\n");
        return;
    }

    uint8_t subseed[32] = { 0 };
    uint8_t privateKey[32] = { 0 };
    uint8_t sourcePublicKey[32] = { 0 };
    uint8_t destPublicKey[32] = { 0 };
    uint8_t digest[32];
    uint8_t signature[64];
    char publicIdentity[128] = { 0 };
    char txHash[128] = { 0 };
    const bool isLowerCase = false;

    //
    // Common part to getting all the keys(public, private) from seed
    //
    getSubseedFromSeed((uint8_t*) seed, subseed);
    getPrivateKeyFromSubSeed(subseed, privateKey);
    getPublicKeyFromPrivateKey(privateKey, sourcePublicKey);
    getIdentityFromPublicKey(sourcePublicKey, publicIdentity, isLowerCase);
    memset(destPublicKey, 0, 32);
    ((uint64_t*) destPublicKey)[0] = QLOAN_CONTRACT_INDEX;

    struct {
        RequestResponseHeader header;
        Transaction transaction;
        payLoanDebt_input inputData;
        uint8_t sig[64];
    } packet;

    //
    // Filling the transaction packet to send
    //
    memset(&packet, 0, sizeof(packet));
    memcpy(packet.transaction.sourcePublicKey, sourcePublicKey, 32);
    memcpy(packet.transaction.destinationPublicKey, destPublicKey, 32);
    packet.transaction.amount = 100;
    uint32_t currentTick = getTickNumberFromNode(qc);
    packet.transaction.tick = currentTick + scheduledTickOffset;
    packet.transaction.inputType = QLOAN_PAY_DEBT;
    packet.transaction.inputSize = sizeof(input);
    memcpy(&packet.inputData, &input, sizeof(input));

    //
    // Crypto magic to sign my transaction with private key, i guess
    //
    KangarooTwelve((uint8_t*)&packet.transaction,
                   sizeof(packet.transaction) + sizeof(input),
                   digest, 
                   32);
    sign(subseed, sourcePublicKey, digest, signature);
    memcpy(packet.sig, signature, 64);
    packet.header.setSize(sizeof(packet));
    packet.header.zeroDejavu();
    packet.header.setType(BROADCAST_TRANSACTION);

    //
    // Sending transaction itself
    //
    qc->sendData((uint8_t*)&packet, packet.header.size());

    KangarooTwelve((uint8_t*)&packet.transaction, 
                   sizeof(packet.transaction) + sizeof(input) + SIGNATURE_SIZE, 
                   digest,
                   32);
    getTxHashFromDigest(digest, txHash);
    printReceipt(packet.transaction, txHash, nullptr);
    LOG("\n%u\n", currentTick);
    LOG("run ./qubic-cli [...] -checktxontick %u %s\n", currentTick + scheduledTickOffset, txHash);
    LOG("to check your tx confirmation status\n");
}

void qloanReleaseAsset(const char* nodeIp, int nodePort,
                       const char* seed,
                       const char* assetIssuer,
                       const char* assetName,
                       const uint64_t toReleaseAmount,
                       const uint16_t dstManagingContractIdx,
                       const uint32_t scheduledTickOffset)
{
    releaseAsset_input input;
    memset(&input, 0, sizeof(releaseAsset_input));
    getPublicKeyFromIdentity(assetIssuer, input.assetIssuer);
    memcpy(&input.assetName, assetName, strlen(assetName));
    input.toReleaseAmount = toReleaseAmount;
    input.dstManagingContractIdx = dstManagingContractIdx;

    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) {
        LOG("Failed to connect to node.\n");
        return;
    }

    uint8_t subseed[32] = { 0 };
    uint8_t privateKey[32] = { 0 };
    uint8_t sourcePublicKey[32] = { 0 };
    uint8_t destPublicKey[32] = { 0 };
    uint8_t digest[32];
    uint8_t signature[64];
    char publicIdentity[128] = { 0 };
    char txHash[128] = { 0 };
    const bool isLowerCase = false;

    //
    // Common part to getting all the keys(public, private) from seed
    //
    getSubseedFromSeed((uint8_t*) seed, subseed);
    getPrivateKeyFromSubSeed(subseed, privateKey);
    getPublicKeyFromPrivateKey(privateKey, sourcePublicKey);
    getIdentityFromPublicKey(sourcePublicKey, publicIdentity, isLowerCase);
    memset(destPublicKey, 0, 32);
    ((uint64_t*) destPublicKey)[0] = QLOAN_CONTRACT_INDEX;

    struct {
        RequestResponseHeader header;
        Transaction transaction;
        releaseAsset_input inputData;
        uint8_t sig[64];
    } packet;

    //
    // Filling the transaction packet to send
    //
    memset(&packet, 0, sizeof(packet));
    memcpy(packet.transaction.sourcePublicKey, sourcePublicKey, 32);
    memcpy(packet.transaction.destinationPublicKey, destPublicKey, 32);
    packet.transaction.amount = 100;
    uint32_t currentTick = getTickNumberFromNode(qc);
    packet.transaction.tick = currentTick + scheduledTickOffset;
    packet.transaction.inputType = QLOAN_RELEASE_ASSET;
    packet.transaction.inputSize = sizeof(input);
    memcpy(&packet.inputData, &input, sizeof(input));

    //
    // Crypto magic to sign my transaction with private key, i guess
    //
    KangarooTwelve((uint8_t*)&packet.transaction,
                   sizeof(packet.transaction) + sizeof(input),
                   digest, 
                   32);
    sign(subseed, sourcePublicKey, digest, signature);
    memcpy(packet.sig, signature, 64);
    packet.header.setSize(sizeof(packet));
    packet.header.zeroDejavu();
    packet.header.setType(BROADCAST_TRANSACTION);

    //
    // Sending transaction itself
    //
    qc->sendData((uint8_t*)&packet, packet.header.size());

    KangarooTwelve((uint8_t*)&packet.transaction, 
                   sizeof(packet.transaction) + sizeof(input) + SIGNATURE_SIZE, 
                   digest,
                   32);
    getTxHashFromDigest(digest, txHash);
    printReceipt(packet.transaction, txHash, nullptr);
    LOG("\n%u\n", currentTick);
    LOG("run ./qubic-cli [...] -checktxontick %u %s\n", currentTick + scheduledTickOffset, txHash);
    LOG("to check your tx confirmation status\n");
}

template<typename T>
static void logLoanReqs(T& t)
{
    std::map<enum LoanReqState, std::string> loanReqStateDescr = {
        {LoanReqState::IDLE, "IDLE"},
        {LoanReqState::ACTIVE, "ACTIVE"},
        {LoanReqState::PAYED, "PAYED"},
        {LoanReqState::EXPIRED, "EXPIRED"},
    };

    std::vector<LoanReq> loan_reqs;
    loan_reqs.insert(loan_reqs.end(), t.loanReqs, t.loanReqs + t.loanReqsAmount);
    std::sort(loan_reqs.begin(), loan_reqs.end(), [](LoanReq& f, LoanReq& s) {return f.reqId < s.reqId;});

    LOG("Loan reqs amount: %ld\n", t.loanReqsAmount);
    for (auto& loan_req : loan_reqs)
    {
        char borrowerId[60];
        char creditorId[60];
        char acceptedById[60];
        char privateId[60];
        getIdentityFromPublicKey(loan_req.borrowerId, borrowerId, false);
        getIdentityFromPublicKey(loan_req.creditorId, creditorId, false);
        getIdentityFromPublicKey(loan_req.acceptedById, acceptedById, false);
        getIdentityFromPublicKey(loan_req.privateId, privateId, false);

        LOG("Borrower: %.60s\nCreditor: %.60s\nAcceptedBy: %.60s\nPrivateId: %.60s\nLoan id: %ld\n",
            borrowerId, 
            creditorId,
            acceptedById,
            privateId,
            loan_req.reqId);

        LOG("Assets amount: %d\n", loan_req.assetsNum);
        LOG("price amount: %ld, interest rate: %ld, debt amount: %ld, return period in epochs: %ld, epochs left: %ld, state: %s\n",
            loan_req.priceAmount,
            loan_req.interestRate,
            loan_req.debtAmount,
            loan_req.returnPeriodInEpochs,
            loan_req.epochsLeft,
            loanReqStateDescr.at(loan_req.state).c_str());
        for (unsigned int j = 0; j < loan_req.assetsNum; j++)
        {
            char assetName[8];
            char assetIssuer[60];

            memcpy(assetName, &loan_req.assets[j].assetName, 8);
            getIdentityFromPublicKey(loan_req.assets[j].assetIssuer, assetIssuer, false);
            LOG("name: %0.8s\nasset issuer: %.60s\nasset amount: %ld\n",
                assetName,
                assetIssuer,
                loan_req.assetAmount[j]);
        }
        LOG("\n");
    }
}

void qloanGetAllLoanReqs(const char* nodeIp, int nodePort)
{
    getAllLoanReqs_input input;

    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) {
        LOG("Failed to connect to node.\n");
        return;
    }

    struct {
        RequestResponseHeader header;
        RequestContractFunction rcf;
        getAllLoanReqs_input in;
    } req;

    memset((void*)&req, 0, sizeof(req));
    req.rcf.contractIndex = QLOAN_CONTRACT_INDEX;
    req.rcf.inputType = QLOAN_GET_ACTIVE_LOAN_REQS;
    req.rcf.inputSize = sizeof(req.in);
    memcpy(&req.in, &input, sizeof(input));

    req.header.setSize(sizeof(req.header) + sizeof(req.rcf) + sizeof(req.in));
    req.header.randomizeDejavu();
    req.header.setType(RequestContractFunction::type());

    qc->sendData((uint8_t*)&req, req.header.size());

    getAllLoanReqs_output output;
    memset((void*)&output, 0, sizeof(output));
    try {
        output = qc->receivePacketWithHeaderAs<getAllLoanReqs_output>();
    }
    catch (std::logic_error) {
        LOG("Failed to get active loans.\n");
        return;
    }

    logLoanReqs(output);
}

void qloanGetUserActiveLoanReqs(const char* nodeIp, int nodePort, const char* userId)
{
    getUserActiveLoanReqs_input input;

    memset(&input, 0, sizeof(input));
    getPublicKeyFromIdentity(userId, input.userId);

    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) {
        LOG("Failed to connect to node.\n");
        return;
    }

    struct {
        RequestResponseHeader header;
        RequestContractFunction rcf;
        getUserActiveLoanReqs_input in;
    } req;

    memset((void*)&req, 0, sizeof(req));
    req.rcf.contractIndex = QLOAN_CONTRACT_INDEX;
    req.rcf.inputType = QLOAN_GET_USER_ACTIVE_LOAN_REQS;
    req.rcf.inputSize = sizeof(req.in);
    memcpy(&req.in, &input, sizeof(input));

    req.header.setSize(sizeof(req.header) + sizeof(req.rcf) + sizeof(req.in));
    req.header.randomizeDejavu();
    req.header.setType(RequestContractFunction::type());

    qc->sendData((uint8_t*)&req, req.header.size());

    getUserActiveLoanReqs_output output;
    memset((void*)&output, 0, sizeof(output));
    try {
        output = qc->receivePacketWithHeaderAs<getUserActiveLoanReqs_output>();
    }
    catch (std::logic_error) {
        LOG("Failed to get active loans.\n");
        return;
    }

    logLoanReqs(output);
}

void qloanGetUserAcceptedLoanReqs(const char* nodeIp, int nodePort, const char* userId)
{
    getUserAcceptedLoanReqs_input input;

    memset(&input, 0, sizeof(input));
    getPublicKeyFromIdentity(userId, input.userId);

    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) {
        LOG("Failed to connect to node.\n");
        return;
    }

    struct {
        RequestResponseHeader header;
        RequestContractFunction rcf;
        getUserAcceptedLoanReqs_input in;
    } req;

    memset((void*)&req, 0, sizeof(req));
    req.rcf.contractIndex = QLOAN_CONTRACT_INDEX;
    req.rcf.inputType = QLOAN_GET_USER_ACCEPTED_LOAN_REQS;
    req.rcf.inputSize = sizeof(req.in);
    memcpy(&req.in, &input, sizeof(input));

    req.header.setSize(sizeof(req.header) + sizeof(req.rcf) + sizeof(req.in));
    req.header.randomizeDejavu();
    req.header.setType(RequestContractFunction::type());

    qc->sendData((uint8_t*)&req, req.header.size());

    getUserAcceptedLoanReqs_output output;
    memset((void*)&output, 0, sizeof(output));
    try {
        output = qc->receivePacketWithHeaderAs<getUserAcceptedLoanReqs_output>();
    }
    catch (std::logic_error) {
        LOG("Failed to get active loans.\n");
        return;
    }

    logLoanReqs(output);
}

void qloanGetFees(const char* nodeIp, int nodePort)
{
    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) {
        LOG("Failed to connect to node.\n");
        return;
    }

    struct {
        RequestResponseHeader header;
        RequestContractFunction rcf;
        getFeesInfo_input in;
    } req;

    memset((void*)&req, 0, sizeof(req));
    req.rcf.contractIndex = QLOAN_CONTRACT_INDEX;
    req.rcf.inputType = QLOAN_GET_FEES;
    req.rcf.inputSize = sizeof(req.in);
    //memcpy(&req.in, &input, sizeof(input));

    req.header.setSize(sizeof(req.header) + sizeof(req.rcf) + sizeof(req.in));
    req.header.randomizeDejavu();
    req.header.setType(RequestContractFunction::type());

    qc->sendData((uint8_t*)&req, req.header.size());

    getFeesInfo_output output;
    memset((void*)&output, 0, sizeof(output));
    try {
        output = qc->receivePacketWithHeaderAs<getFeesInfo_output>();
    }
    catch (std::logic_error) {
        LOG("Failed to get fees info.\n");
        return;
    }
    LOG("Loan acceptance fee percent: %ld\n", output.acceptanceFeePercent);
    LOG("Loan distribute fee percent: %ld\n", output.distributeFeePercent);
    LOG("Loan burn fee percent: %ld\n\n", output.burnFeePercent);

    LOG("Loan earned amount: %ld\n", output.earnedAmount);
    LOG("Loan distributed amount: %ld\n", output.distributedAmount);
    LOG("Loan burned amount: %ld\n", output.burnedAmount);
    LOG("Loan to devs amount: %ld\n", output.toDevsAmount);
}

void qloanGetUserDebt(const char* nodeIp, int nodePort, const char* userId)
{
    getUserDebt_input input;

    getPublicKeyFromIdentity(userId, input.userId);

    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) {
        LOG("Failed to connect to node.\n");
        return;
    }

    struct {
        RequestResponseHeader header;
        RequestContractFunction rcf;
        getUserDebt_input in;
    } req;

    memset((void*)&req, 0, sizeof(req));
    req.rcf.contractIndex = QLOAN_CONTRACT_INDEX;
    req.rcf.inputType = QLOAN_GET_USER_DEBT;
    req.rcf.inputSize = sizeof(req.in);
    memcpy(&req.in, &input, sizeof(input));

    req.header.setSize(sizeof(req.header) + sizeof(req.rcf) + sizeof(req.in));
    req.header.randomizeDejavu();
    req.header.setType(RequestContractFunction::type());

    qc->sendData((uint8_t*)&req, req.header.size());

    getUserDebt_output output;
    memset((void*)&output, 0, sizeof(output));
    try {
        output = qc->receivePacketWithHeaderAs<getUserDebt_output>();
    }
    catch (std::logic_error) {
        LOG("Failed to get user debt.\n");
        return;
    }

    LOG("Total user debt: %ld\n", output.totalUserDebt);
}
