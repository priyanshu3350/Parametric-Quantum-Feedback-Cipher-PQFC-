%% ============================================================
%  Quantum-Classical Hybrid Cryptosystem
%  Converted from Python (PennyLane) to MATLAB
%  Requires: Quantum Computing Toolbox (R2023a+)
%  ============================================================

clc; 
clearvars; 
close all;

%% ── DEMO ENTRY POINT ────────────────────────────────────────
% Run this section to exercise the full pipeline.

% 1. Build 256-bit quantum seed (32 rounds × 8 bits)
seedBits = zeros(1, 256);
for r = 1:32
    block = getQuantumSeedBlock();          % returns 8 bits (0/1)
    seedBits((r-1)*8+1 : r*8) = block;
end
masterSeed = uint64(0);
for i = 1:64
    masterSeed = bitor(bitshift(masterSeed, 1), uint64(seedBits(192+i)));
end
% 256-bit integer as uint64 (lower 64 bits)

% 2. Generate a random plaintext message (~10KB for demo)
rng(42);
msgLen    = 10000;
plaintext = uint8(randi([32 126], 1, msgLen));      % printable ASCII

fprintf('\n256-bit Quantum Seed (lower 64 bits): 0x%s\n', dec2hex(masterSeed));
fprintf('Message length: %.2f KB\n', msgLen/1024);

% Start total timer
totalTimeStart = tic;

% 3. Benchmark Loop
fprintf('\n--- Benchmarking ---\n');
numRounds = 20;
fprintf('Executing %d rounds for perfectly smoothed OS timing averages. (This will take a few minutes for ARX!)\n', numRounds);

totalEncTime = 0.0;
totalDecTime = 0.0;
for r = 1:numRounds
    encStart = tic;
    ciphertext  = qcEncrypt(plaintext,  masterSeed);
    totalEncTime = totalEncTime + toc(encStart);
    
    decStart = tic;
    decrypted   = qcDecrypt(ciphertext, masterSeed);
    totalDecTime = totalDecTime + toc(decStart);
end

arxEncTime = totalEncTime / numRounds;
arxDecTime = totalDecTime / numRounds;

fprintf('Encryption Time (Avg): %.4f seconds\n', arxEncTime);
fprintf('Decryption Time (Avg): %.4f seconds\n', arxDecTime);

% Total Time
totalTime = toc(totalTimeStart);
fprintf('Total Overhead (including verification): %.4f seconds\n', totalTime);

% Message Length Comparison
lenPlain = numel(plaintext);
lenCipher = numel(ciphertext);
fprintf('Length Change: %d bytes (Plaintext: %d -> Ciphertext: %d)\n', lenCipher - lenPlain, lenPlain, lenCipher);

assert(isequal(plaintext, decrypted), 'Decryption failed!');
fprintf('\nDecryption verified OK.\n');

% 5. Metrics
H = shannonEntropy(ciphertext);
fprintf('Shannon Entropy: %.4f bits/symbol\n', H);

% 6. Avalanche effect test
text2    = plaintext;
text2(1) = bitxor(text2(1), uint8(1));     % flip 1 bit

cipher1 = qcEncrypt(plaintext, masterSeed);
cipher2 = qcEncrypt(text2,     masterSeed);
ae      = avalancheEffect(cipher1, cipher2);
fprintf('\nAvalanche Effect Score: %.2f%%\n', ae);

%% 7. =========================================================
%  CLASSICAL COMPARSION BENCHMARKS (AES, 3DES, ECB)
%  ============================================================
% Java dependencies for classical crypto
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

fprintf('\n[ Generating Standard Baseline Averages (%d Rounds) ]\n', numRounds);
msgMod = plaintext;
msgMod(1) = bitxor(msgMod(1), uint8(1));

% Sync existing ARX cipher variables for metrics below
qCipher = ciphertext;

qCipher2 = qcEncrypt(msgMod, masterSeed);
arxAe = avalancheEffect(qCipher, qCipher2);

qMasterSeedMod = bitxor(masterSeed, uint64(1));
qCipher3 = qcEncrypt(plaintext, qMasterSeedMod);
arxKae = avalancheEffect(qCipher, qCipher3);

arxEnt = shannonEntropy(qCipher);
arxLen = numel(qCipher) - numel(plaintext);

%% 7.1 Benchmark AES-256 (CBC mode via Java)
aesKey = uint8(randi([0 255], 1, 32));
aesIv  = uint8(randi([0 255], 1, 16));
secretKey = SecretKeySpec(typecast(aesKey, 'int8'), 'AES');
ivSpec    = IvParameterSpec(typecast(aesIv, 'int8'));
aesCipherObj = Cipher.getInstance('AES/CBC/PKCS5Padding');

totalEncTime = 0.0;
totalDecTime = 0.0;
for r = 1:numRounds
    encStart = tic;
    aesCipherObj.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
    aesCipherBytes = typecast(aesCipherObj.doFinal(typecast(plaintext, 'int8')), 'uint8');
    totalEncTime = totalEncTime + toc(encStart);
    
    decStart = tic;
    aesCipherObj.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
    aesPlainBytes = typecast(aesCipherObj.doFinal(typecast(aesCipherBytes, 'int8')), 'uint8');
    totalDecTime = totalDecTime + toc(decStart);
end

aesEncTime = totalEncTime / numRounds;
aesDecTime = totalDecTime / numRounds;

finalAesCipher = [aesIv, aesCipherBytes'];

aesCipherObj.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
aesCipherBytes2 = typecast(aesCipherObj.doFinal(typecast(msgMod, 'int8')), 'uint8');
finalAesCipher2 = [aesIv, aesCipherBytes2'];

minLen = min(numel(finalAesCipher), numel(finalAesCipher2));
aesAe = avalancheEffect(finalAesCipher(1:minLen), finalAesCipher2(1:minLen));

aesKeyMod = aesKey;
aesKeyMod(1) = bitxor(aesKeyMod(1), uint8(1));
secretKeyMod = SecretKeySpec(typecast(aesKeyMod, 'int8'), 'AES');
aesCipherObj.init(Cipher.ENCRYPT_MODE, secretKeyMod, ivSpec);
aesCipherBytes3 = typecast(aesCipherObj.doFinal(typecast(plaintext, 'int8')), 'uint8');
finalAesCipher3 = [aesIv, aesCipherBytes3'];

minLenK = min(numel(finalAesCipher), numel(finalAesCipher3));
aesKae = avalancheEffect(finalAesCipher(1:minLenK), finalAesCipher3(1:minLenK));
aesEnt = shannonEntropy(finalAesCipher);
aesLen = numel(finalAesCipher) - numel(plaintext);

%% 7.2 Benchmark 3DES (Legacy Baseline)
desKey = uint8(randi([0 255], 1, 24));
desIv  = uint8(randi([0 255], 1, 8));
desSecretKey = SecretKeySpec(typecast(desKey, 'int8'), 'DESede');
desIvSpec    = IvParameterSpec(typecast(desIv, 'int8'));
desCipherObj = Cipher.getInstance('DESede/CBC/PKCS5Padding');

totalEncTime = 0.0;
totalDecTime = 0.0;
for r = 1:numRounds
    encStart = tic;
    desCipherObj.init(Cipher.ENCRYPT_MODE, desSecretKey, desIvSpec);
    desCipherBytes = typecast(desCipherObj.doFinal(typecast(plaintext, 'int8')), 'uint8');
    totalEncTime = totalEncTime + toc(encStart);
    
    decStart = tic;
    desCipherObj.init(Cipher.DECRYPT_MODE, desSecretKey, desIvSpec);
    desPlainBytes = typecast(desCipherObj.doFinal(typecast(desCipherBytes, 'int8')), 'uint8');
    totalDecTime = totalDecTime + toc(decStart);
end

desEncTime = totalEncTime / numRounds;
desDecTime = totalDecTime / numRounds;

finalDesCipher = [desIv, desCipherBytes'];

desCipherObj.init(Cipher.ENCRYPT_MODE, desSecretKey, desIvSpec);
desCipherBytes2 = typecast(desCipherObj.doFinal(typecast(msgMod, 'int8')), 'uint8');
finalDesCipher2 = [desIv, desCipherBytes2'];

minLen = min(numel(finalDesCipher), numel(finalDesCipher2));
desAe = avalancheEffect(finalDesCipher(1:minLen), finalDesCipher2(1:minLen));

desKeyMod = desKey;
desKeyMod(1) = bitxor(desKeyMod(1), uint8(2)); % Flip bit 2 because DES ignores bit 1 (parity bit)
desSecretKeyMod = SecretKeySpec(typecast(desKeyMod, 'int8'), 'DESede');
desCipherObj.init(Cipher.ENCRYPT_MODE, desSecretKeyMod, desIvSpec);
desCipherBytes3 = typecast(desCipherObj.doFinal(typecast(plaintext, 'int8')), 'uint8');
finalDesCipher3 = [desIv, desCipherBytes3'];

minLenK = min(numel(finalDesCipher), numel(finalDesCipher3));
desKae = avalancheEffect(finalDesCipher(1:minLenK), finalDesCipher3(1:minLenK));
desEnt = shannonEntropy(finalDesCipher);
desLen = numel(finalDesCipher) - numel(plaintext);

%% 7.3 Benchmark AES-ECB (Insecure Mode Demo)
ecbKey = uint8(randi([0 255], 1, 16));
ecbSecretKey = SecretKeySpec(typecast(ecbKey, 'int8'), 'AES');
ecbCipherObj = Cipher.getInstance('AES/ECB/PKCS5Padding');

totalEncTime = 0.0;
totalDecTime = 0.0;
for r = 1:numRounds
    encStart = tic;
    ecbCipherObj.init(Cipher.ENCRYPT_MODE, ecbSecretKey);
    ecbCipherBytes = typecast(ecbCipherObj.doFinal(typecast(plaintext, 'int8')), 'uint8');
    totalEncTime = totalEncTime + toc(encStart);
    
    decStart = tic;
    ecbCipherObj.init(Cipher.DECRYPT_MODE, ecbSecretKey);
    ecbPlainBytes = typecast(ecbCipherObj.doFinal(typecast(ecbCipherBytes, 'int8')), 'uint8');
    totalDecTime = totalDecTime + toc(decStart);
end

ecbEncTime = totalEncTime / numRounds;
ecbDecTime = totalDecTime / numRounds;

finalEcbCipher = ecbCipherBytes';

ecbCipherObj.init(Cipher.ENCRYPT_MODE, ecbSecretKey);
ecbCipherBytes2 = typecast(ecbCipherObj.doFinal(typecast(msgMod, 'int8')), 'uint8');
finalEcbCipher2 = ecbCipherBytes2';

minLen = min(numel(finalEcbCipher), numel(finalEcbCipher2));
ecbAe = avalancheEffect(finalEcbCipher(1:minLen), finalEcbCipher2(1:minLen));

ecbKeyMod = ecbKey;
ecbKeyMod(1) = bitxor(ecbKeyMod(1), uint8(1));
ecbSecretKeyMod = SecretKeySpec(typecast(ecbKeyMod, 'int8'), 'AES');
ecbCipherObj.init(Cipher.ENCRYPT_MODE, ecbSecretKeyMod);
ecbCipherBytes3 = typecast(ecbCipherObj.doFinal(typecast(plaintext, 'int8')), 'uint8');
finalEcbCipher3 = ecbCipherBytes3';

minLenK = min(numel(finalEcbCipher), numel(finalEcbCipher3));
ecbKae = avalancheEffect(finalEcbCipher(1:minLenK), finalEcbCipher3(1:minLenK));
ecbEnt = shannonEntropy(finalEcbCipher);
ecbLen = numel(finalEcbCipher) - numel(plaintext);

% Compute NIST SP 800-22 Tests
arxNMon = nistMonobitTest(qCipher);
arxNBlk = nistBlockFrequencyTest(qCipher, 128);
arxNRun = nistRunsTest(qCipher);

aesNMon = nistMonobitTest(finalAesCipher);
aesNBlk = nistBlockFrequencyTest(finalAesCipher, 128);
aesNRun = nistRunsTest(finalAesCipher);

desNMon = nistMonobitTest(finalDesCipher);
desNBlk = nistBlockFrequencyTest(finalDesCipher, 128);
desNRun = nistRunsTest(finalDesCipher);

ecbNMon = nistMonobitTest(finalEcbCipher);
ecbNBlk = nistBlockFrequencyTest(finalEcbCipher, 128);
ecbNRun = nistRunsTest(finalEcbCipher);

%% 7.4 Print Comparison Grid
fprintf('\n======================== BENCHMARK RESULTS ========================\n');
fprintf('%-16s | %-10s | %-10s | %-8s | %-10s\n', 'Metric', 'Q-ARX', 'AES-CBC', '3DES', 'AES-ECB');
fprintf('-------------------------------------------------------------------\n');
fprintf('%-16s | %-10.4f | %-10.4f | %-8.4f | %-10.4f\n', 'Enc Time (s)', arxEncTime, aesEncTime, desEncTime, ecbEncTime);
fprintf('%-16s | %-10.4f | %-10.4f | %-8.4f | %-10.4f\n', 'Dec Time (s)', arxDecTime, aesDecTime, desDecTime, ecbDecTime);
fprintf('%-16s | %-10d | %-10d | %-8d | %-10d\n', 'Overhead (B)', arxLen, aesLen, desLen, ecbLen);
fprintf('%-16s | %-10.4f | %-10.4f | %-8.4f | %-10.4f\n', 'Entropy', arxEnt, aesEnt, desEnt, ecbEnt);
fprintf('%-16s | %-10.2f | %-10.2f | %-8.2f | %-10.2f\n', 'Plain Aval (%)', arxAe, aesAe, desAe, ecbAe);
fprintf('%-16s | %-10.2f | %-10.2f | %-8.2f | %-10.2f\n', 'Key Aval (%)', arxKae, aesKae, desKae, ecbKae);
fprintf('%-16s | %-10.4f | %-10.4f | %-8.4f | %-10.4f\n', 'NIST Monobit', arxNMon, aesNMon, desNMon, ecbNMon);
fprintf('%-16s | %-10.4f | %-10.4f | %-8.4f | %-10.4f\n', 'NIST Block', arxNBlk, aesNBlk, desNBlk, ecbNBlk);
fprintf('%-16s | %-10.4f | %-10.4f | %-8.4f | %-10.4f\n', 'NIST Runs', arxNRun, aesNRun, desNRun, ecbNRun);
fprintf('===================================================================\n');



%% ============================================================
%  QUANTUM LAYER
%% ============================================================

function bits = getQuantumSeedBlock()
%GETQUANTUMSEEDBLOCK  Returns 8 measurement bits via 4 Hadamard gates.
%
% Python equivalent:
%   @qml.qnode(dev_seed, shots=1)
%   def get_quantum_seed_block():
%       for i in range(0,8,2): qml.Hadamard(wires=i)
%       return [qml.sample(qml.PauliZ(i)) for i in range(8)]
%
% Note: The original circuit applied H only to even qubits (0,2,4,6)
% and sampled all 8 qubits.  MATLAB is 1-indexed; qubit k (0-based)
% becomes qubit k+1 here.

    nQubits = 8;
    gates   = [];

    % Apply H to qubits 1,3,5,7 (0-based: 0,2,4,6)
    for q = 1:2:nQubits
        gates = [gates, hGate(q)]; %#ok<AGROW>
    end

    circuit = quantumCircuit(gates);
    state   = simulate(circuit);          % returns quantumState object

    % Sample once from the measurement probability distribution
    % (equivalent to shots=1 in PennyLane)
    sv        = state.Amplitudes(:);              % force column vector
    probs     = abs(sv).^2;
    probs     = real(probs) / sum(real(probs));  % normalise for floating errors

    numStates = numel(probs);                    % derive from actual amplitudes
    outcome   = randsample(0:numStates-1, 1, true, probs);

    % Decode outcome into exactly nQubits bits (big-endian, LSB = qubit 1)
    rawBits = fliplr(dec2bin(outcome, nQubits) - '0');  % always 1×nQubits

    % Invert: PauliZ +1 eigenvalue → bit 0,  -1 → bit 1 (matches Python)
    rawBits = 1 - rawBits;

    % Hard-guarantee 8 output bits in case circuit/amplitude size differs
    rawBits = rawBits(:)';                      % ensure row vector
    if numel(rawBits) >= 8
        bits = rawBits(1:8);
    else
        bits = [rawBits, zeros(1, 8 - numel(rawBits))];
    end
end


function zExp = pqcCircuit(angles)
%PQCCIRCUIT  4-qubit Parameterised Quantum Circuit.
%   angles – 1×4 vector of RY rotation angles (radians)
%   zExp   – 1×4 vector of Pauli-Z expectation values ∈ [-1,+1]
%
% Python equivalent:
%   @qml.qnode(dev_dynamic)
%   def pqc_circuit(angles):
%       for i in range(4): qml.RY(angles[i], wires=i)
%       qml.CNOT([0,1]); qml.CNOT([1,2]); qml.CNOT([2,3]); qml.CNOT([3,0])
%       return [qml.expval(qml.PauliZ(i)) for i in range(4)]

    nQ   = 4;
    gates = [ ...
        ryGate(1, angles(1)), ...
        ryGate(2, angles(2)), ...
        ryGate(3, angles(3)), ...
        ryGate(4, angles(4)), ...
        cxGate(1,2), ...
        cxGate(2,3), ...
        cxGate(3,4), ...
        cxGate(4,1)  ...
    ];

    circuit = quantumCircuit(gates);
    state   = simulate(circuit);
    sv      = state.Amplitudes;     % try .State or .Data if this errors

    % Compute <Z_k> = Σ_x |ψ_x|² · (-1)^{bit_k(x)}
    probs = abs(sv).^2;
    zExp  = zeros(1, nQ);
    for k = 1:nQ
        % bit k of basis index x (0-based):
        %   bitPosition = nQ - k  (big-endian: qubit 1 is MSB)
        sign = zeros(2^nQ, 1);
        for x = 0 : 2^nQ-1
            bitVal  = bitand(bitshift(x, -(nQ-k)), 1);   % bit of qubit k (0-based col nQ-k)
            sign(x+1) = 1 - 2*bitVal;                    % 0→+1,  1→-1
        end
        zExp(k) = dot(probs, sign);
    end
end


function zExp = simulatePQC(state32)
%SIMULATEPQC  Maps a 32-bit classical state to PQC rotation angles and runs circuit.
%   state32 – uint32 or double scalar (treated as 32-bit unsigned)
%
% Python equivalent:
%   def simulate_pqc(state_32bit):
%       angles = [((state_32bit >> (8*i)) & 0xFF) / 255.0 * pi for i in range(4)]
%       return np.array(pqc_circuit(angles))

    s = double(uint32(state32));
    angles = zeros(1,4);
    for i = 0:3
        byte_i   = double(bitand(bitshift(uint32(s), -8*i), uint32(255)));
        angles(i+1) = (byte_i / 255.0) * pi;
    end
    zExp = pqcCircuit(angles);
end


%% ============================================================
%  CLASSICAL CRYPTOGRAPHIC LAYER
%% ============================================================

function [aNew, cNew] = updateLCGParams(zExp)
%UPDATELCGPARAMS  Derive new LCG multiplier and increment from quantum expectations.
%
% Python equivalent:
%   def update_lcg_params(z_expects):
%       c_raw = int(abs(z_expects[0]) * (2**32-1)); c_new = c_raw | 1
%       a_raw = int(abs(z_expects[1]) * (2**32-1)); a_new = (a_raw & ~3) | 1
%       return a_new, c_new

    MAX32 = double(intmax('uint32'));      % 2^32 - 1 = 4294967295

    cRaw = uint32(floor(abs(zExp(1)) * MAX32));
    cNew = bitor(cRaw, uint32(1));                    % force odd

    aRaw = uint32(floor(abs(zExp(2)) * MAX32));
    aNew = bitor(bitand(aRaw, bitcmp(uint32(3), 'uint32')), uint32(1));  % a = 1 mod 4
end


function sbox = generateQPPSbox(zExp, state32)
%GENERATEQPPSBOX  Dynamic S-Box via quantum-coupled chaotic map.
%
% Python equivalent:
%   def generate_qpp_sbox(z_expects, state_32bit): ...

    s32      = uint32(state32);
    qVal     = double(zExp(2));
    qStep    = double(zExp(3));
    chaoticSeq = zeros(1, 256);

    for i = 0:255
        byteIdx  = mod(i, 4);
        stateByte = double(bitand(bitshift(s32, -8*byteIdx), uint32(255)));
        qVal     = sin(qVal + qStep + (stateByte / 255.0) * pi);
        chaoticSeq(i+1) = qVal;
        qStep    = cos(qStep + double(zExp(mod(i,4)+1)));
    end

    % argsort → MATLAB equivalent: sort and return indices (0-based for byte values)
    [~, sortedIdx] = sort(chaoticSeq);
    sbox = uint8(sortedIdx - 1);   % 0-based output indices, length 256
end


function y = rotl8(x, shift)
%ROTL8  8-bit left circular shift.
    shift = mod(shift, 8);
    x = uint8(x);
    y = bitor(bitshift(x,  shift,  'uint8'), ...
              bitshift(x, -(8-shift), 'uint8'));
end


function y = rotr8(x, shift)
%ROTR8  8-bit right circular shift.
    shift = mod(shift, 8);
    x = uint8(x);
    y = bitor(bitshift(x, -shift, 'uint8'), ...
              bitshift(x,  8-shift, 'uint8'));
end


%% ============================================================
%  ENCRYPT / DECRYPT
%% ============================================================

function ciphertext = qcEncrypt(plaintext, masterSeed)
%QCENCRYPT  Encrypt a uint8 vector using the quantum-classical cipher.
%
% Python equivalent:
%   def encrypt(plaintext, master_seed): ...

    plaintext  = uint8(plaintext);
    n          = numel(plaintext);
    ciphertext = zeros(1, n, 'uint8');

    % Truncate to lower 32 bits (prevents uint32 saturation)
    xn    = uint32(bitand(masterSeed, uint64(4294967295)));   
    prevC = uint8(0);

    for idx = 1:n
        p      = plaintext(idx);
        zExp   = simulatePQC(double(xn));

        [~, cI]   = updateLCGParams(zExp);    % aI unused in key stream here (used for state update)
        [aI, ~]   = updateLCGParams(zExp);    %   retrieve both cleanly
        sbox      = generateQPPSbox(zExp, double(xn));

        rawLCGByte = uint8(bitand(bitshift(xn, -24), uint32(255)));
        kI         = sbox(double(rawLCGByte)+1);      % MATLAB 1-indexed

        rI = uint8(floor(abs(zExp(4)) * 7));

        modAdd   = uint8(mod(double(p) + double(kI), 256));
        rotated  = rotl8(modAdd, double(rI));
        ciByte   = bitxor(rotated, prevC);

        ciphertext(idx) = ciByte;
        prevC = ciByte;

        % State update: xn = (aI * (xn XOR prevC) + cI) mod 2^32
        xnXorC = bitxor(xn, uint32(prevC));
        nextXn = uint64(aI) * uint64(xnXorC) + uint64(cI);
        xn     = uint32(bitand(nextXn, uint64(4294967295)));
    end
end


function plaintext = qcDecrypt(ciphertext, masterSeed)
%QCDECRYPT  Decrypt a uint8 vector using the quantum-classical cipher.
%
% Python equivalent:
%   def decrypt(ciphertext, master_seed): ...

    ciphertext = uint8(ciphertext);
    n          = numel(ciphertext);
    plaintext  = zeros(1, n, 'uint8');

    % Truncate to lower 32 bits (prevents uint32 saturation)
    xn    = uint32(bitand(masterSeed, uint64(4294967295)));
    prevC = uint8(0);

    for idx = 1:n
        c    = ciphertext(idx);
        zExp = simulatePQC(double(xn));

        [aI, ~]  = updateLCGParams(zExp);
        [~, cI]  = updateLCGParams(zExp);
        sbox     = generateQPPSbox(zExp, double(xn));

        rawLCGByte = uint8(bitand(bitshift(xn, -24), uint32(255)));
        kI         = sbox(double(rawLCGByte)+1);

        rI = uint8(floor(abs(zExp(4)) * 7));

        unXor = bitxor(c, prevC);
        unRot = rotr8(unXor, double(rI));
        p     = uint8(mod(double(unRot) - double(kI), 256));

        plaintext(idx) = p;
        prevC = c;

        xnXorC = bitxor(xn, uint32(prevC));
        nextXn = uint64(aI) * uint64(xnXorC) + uint64(cI);
        xn     = uint32(bitand(nextXn, uint64(4294967295)));
    end
end


%% ============================================================
%  METRICS
%% ============================================================

function H = shannonEntropy(data)
%SHANNONENTROPY  Computes Shannon entropy of a uint8 vector (bits/symbol).
%
% Python equivalent: calculate_shannon_entropy

    data   = double(data(:));
    counts = histcounts(data, 0:256);   % bins 0–255
    counts = counts(counts > 0);
    n      = sum(counts);
    p      = counts / n;
    H      = -sum(p .* log2(p));
end


function score = avalancheEffect(cipher1, cipher2)
%AVALANCHEEFFECT  Percentage of bit flips between two equal-length ciphertexts.
%
% Python equivalent: calculate_avalanche_effect

    if numel(cipher1) ~= numel(cipher2)
        error('Ciphertexts must be the same length.');
    end
    xorBytes    = bitxor(uint8(cipher1), uint8(cipher2));
    flippedBits = sum(arrayfun(@(b) sum(dec2bin(b,'8')-'0'), xorBytes));
    totalBits   = numel(cipher1) * 8;
    score       = (flippedBits / totalBits) * 100.0;
end


function pValue = nistMonobitTest(data)
%NISTMONOBITTEST Frequency (Monobit) Test from NIST SP 800-22
    bits = dec2bin(uint8(data), 8)' - '0';
    bits = bits(:); % Convert to column vector of 1s and 0s
    n = numel(bits);
    if n == 0
        pValue = 0;
        return;
    end
    S = sum(bits == 1) - sum(bits == 0);
    sObs = abs(S) / sqrt(n);
    pValue = erfc(sObs / sqrt(2));
end


function pValue = nistBlockFrequencyTest(data, M)
%NISTBLOCKFREQUENCYTEST Block Frequency Test from NIST SP 800-22
    if nargin < 2
        M = 128;
    end
    bits = dec2bin(uint8(data), 8)' - '0';
    bits = bits(:);
    n = numel(bits);
    if n == 0
        pValue = 0;
        return;
    end
    N = floor(n / M);
    if N == 0
        pValue = 0;
        return;
    end
    
    chiSquareObs = 0.0;
    for i = 1:N
        block = bits((i-1)*M + 1 : i*M);
        pi_i = sum(block) / M;
        chiSquareObs = chiSquareObs + (pi_i - 0.5)^2;
    end
    chiSquareObs = chiSquareObs * 4 * M;
    
    pValue = gammainc(chiSquareObs / 2, N / 2, 'upper');
end


function pValue = nistRunsTest(data)
%NISTRUNSTEST Runs Test from NIST SP 800-22
    bits = dec2bin(uint8(data), 8)' - '0';
    bits = bits(:);
    n = numel(bits);
    if n == 0
        pValue = 0;
        return;
    end
    
    onesFreq = sum(bits) / n;
    tau = 2 / sqrt(n);
    if abs(onesFreq - 0.5) >= tau
        pValue = 0.0;
        return;
    end
    
    vnObs = 1 + sum(bits(1:end-1) ~= bits(2:end));
    
    num = abs(vnObs - 2 * n * onesFreq * (1 - onesFreq));
    den = 2 * sqrt(2 * n) * onesFreq * (1 - onesFreq);
    
    if den == 0
        pValue = 0.0;
    else
        pValue = erfc(num / den);
    end
end