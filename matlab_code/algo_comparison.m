function result = algo_comparison()
% ALGO_COMPARISON benchmarks the Quantum-ARX cipher against AES-256 and ChaCha20
% utilizing MATLAB's built-in native Java cryptographic wrappers.

    rng(42);
    msgLen = 10000;
    fprintf('Creating a standardized benchmark using Plaintext Length: %d Bytes.\n', msgLen);
    message = uint8(randi([0 255], 1, msgLen));
    
    % Generate equivalent keys
    qSeedArray = uint8(randi([0 255], 1, 32));
    qMasterSeed = uint64(0);
    for i = 1:64
        qMasterSeed = bitor(bitshift(qMasterSeed, 1), uint64(mod(qSeedArray(min(i,32)), 2)));
    end
    
    % Java dependencies for classical crypto
    import javax.crypto.Cipher;
    import javax.crypto.spec.SecretKeySpec;
    import javax.crypto.spec.IvParameterSpec;
    
    %% 1. Benchmark Quantum-ARX
    fprintf('\n[ Quantum-ARX Hybrid Cipher ]\n');
    encStart = tic;
    qCipher = qcEncrypt(message, qMasterSeed);
    arxEncTime = toc(encStart);
    
    decStart = tic;
    qPlain = qcDecrypt(qCipher, qMasterSeed);
    arxDecTime = toc(decStart);
    
    msgMod = message;
    msgMod(1) = bitxor(msgMod(1), uint8(1));
    qCipher2 = qcEncrypt(msgMod, qMasterSeed);
    arxAe = avalanche_effect(qCipher, qCipher2);
    
    qMasterSeedMod = bitxor(qMasterSeed, uint64(1));
    qCipher3 = qcEncrypt(message, qMasterSeedMod);
    arxKae = avalanche_effect(qCipher, qCipher3);
    
    arxEnt = shannon_entropy(qCipher);
    arxLen = numel(qCipher) - numel(message);
    
    %% 2. Benchmark AES-256 (CBC mode via Java)
    fprintf('[ AES-256-CBC Baseline ]\n');
    aesKey = uint8(randi([0 255], 1, 32));
    aesIv  = uint8(randi([0 255], 1, 16));
    secretKey = SecretKeySpec(int8(aesKey), 'AES');
    ivSpec    = IvParameterSpec(int8(aesIv));
    
    aesCipherObj = Cipher.getInstance('AES/CBC/PKCS5Padding');
    
    encStart = tic;
    aesCipherObj.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
    aesCipherBytes = typecast(aesCipherObj.doFinal(int8(message)), 'uint8');
    aesEncTime = toc(encStart);
    
    % Final ciphertext includes IV overhead naturally in block ciphers
    finalAesCipher = [aesIv, aesCipherBytes'];
    
    decStart = tic;
    aesCipherObj.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
    aesPlainBytes = typecast(aesCipherObj.doFinal(int8(aesCipherBytes)), 'uint8');
    aesDecTime = toc(decStart);
    
    aesCipherObj.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
    aesCipherBytes2 = typecast(aesCipherObj.doFinal(int8(msgMod)), 'uint8');
    finalAesCipher2 = [aesIv, aesCipherBytes2'];
    
    minLen = min(numel(finalAesCipher), numel(finalAesCipher2));
    aesAe = avalanche_effect(finalAesCipher(1:minLen), finalAesCipher2(1:minLen));
    
    aesKeyMod = aesKey;
    aesKeyMod(1) = bitxor(aesKeyMod(1), uint8(1));
    secretKeyMod = SecretKeySpec(int8(aesKeyMod), 'AES');
    aesCipherObj.init(Cipher.ENCRYPT_MODE, secretKeyMod, ivSpec);
    aesCipherBytes3 = typecast(aesCipherObj.doFinal(int8(message)), 'uint8');
    finalAesCipher3 = [aesIv, aesCipherBytes3'];
    
    minLenK = min(numel(finalAesCipher), numel(finalAesCipher3));
    aesKae = avalanche_effect(finalAesCipher(1:minLenK), finalAesCipher3(1:minLenK));
    
    aesEnt = shannon_entropy(finalAesCipher);
    aesLen = numel(finalAesCipher) - numel(message);
    
    %% 3. Benchmark 3DES (Triple DES CBC via Java)
    fprintf('[ 3DES-CBC (Legacy Baseline) ]\n');
    desKey = uint8(randi([0 255], 1, 24));
    desIv  = uint8(randi([0 255], 1, 8));
    desSecretKey = SecretKeySpec(int8(desKey), 'DESede');
    desIvSpec    = IvParameterSpec(int8(desIv));
    
    desCipherObj = Cipher.getInstance('DESede/CBC/PKCS5Padding');
    
    encStart = tic;
    desCipherObj.init(Cipher.ENCRYPT_MODE, desSecretKey, desIvSpec);
    desCipherBytes = typecast(desCipherObj.doFinal(int8(message)), 'uint8');
    desEncTime = toc(encStart);
    
    finalDesCipher = [desIv, desCipherBytes'];
    
    decStart = tic;
    desCipherObj.init(Cipher.DECRYPT_MODE, desSecretKey, desIvSpec);
    desPlainBytes = typecast(desCipherObj.doFinal(int8(desCipherBytes)), 'uint8');
    desDecTime = toc(decStart);
    
    desCipherObj.init(Cipher.ENCRYPT_MODE, desSecretKey, desIvSpec);
    desCipherBytes2 = typecast(desCipherObj.doFinal(int8(msgMod)), 'uint8');
    finalDesCipher2 = [desIv, desCipherBytes2'];
    
    minLen = min(numel(finalDesCipher), numel(finalDesCipher2));
    desAe = avalanche_effect(finalDesCipher(1:minLen), finalDesCipher2(1:minLen));
    
    desKeyMod = desKey;
    desKeyMod(1) = bitxor(desKeyMod(1), uint8(1));
    desSecretKeyMod = SecretKeySpec(int8(desKeyMod), 'DESede');
    desCipherObj.init(Cipher.ENCRYPT_MODE, desSecretKeyMod, desIvSpec);
    desCipherBytes3 = typecast(desCipherObj.doFinal(int8(message)), 'uint8');
    finalDesCipher3 = [desIv, desCipherBytes3'];
    
    minLenK = min(numel(finalDesCipher), numel(finalDesCipher3));
    desKae = avalanche_effect(finalDesCipher(1:minLenK), finalDesCipher3(1:minLenK));
    
    desEnt = shannon_entropy(finalDesCipher);
    desLen = numel(finalDesCipher) - numel(message);
    
    %% 4. Benchmark AES-ECB (Demonstration of Insecure Mode)
    fprintf('[ AES-128-ECB (Insecure Mode Demo) ]\n');
    ecbKey = uint8(randi([0 255], 1, 16));
    ecbSecretKey = SecretKeySpec(int8(ecbKey), 'AES');
    
    ecbCipherObj = Cipher.getInstance('AES/ECB/PKCS5Padding');
    
    encStart = tic;
    ecbCipherObj.init(Cipher.ENCRYPT_MODE, ecbSecretKey);
    ecbCipherBytes = typecast(ecbCipherObj.doFinal(int8(message)), 'uint8');
    ecbEncTime = toc(encStart);
    
    finalEcbCipher = ecbCipherBytes';
    
    decStart = tic;
    ecbCipherObj.init(Cipher.DECRYPT_MODE, ecbSecretKey);
    ecbPlainBytes = typecast(ecbCipherObj.doFinal(int8(ecbCipherBytes)), 'uint8');
    ecbDecTime = toc(decStart);
    
    ecbCipherObj.init(Cipher.ENCRYPT_MODE, ecbSecretKey);
    ecbCipherBytes2 = typecast(ecbCipherObj.doFinal(int8(msgMod)), 'uint8');
    finalEcbCipher2 = ecbCipherBytes2';
    
    % ECB fails avalanche extremely poorly because it only flips the first block!
    minLen = min(numel(finalEcbCipher), numel(finalEcbCipher2));
    ecbAe = avalanche_effect(finalEcbCipher(1:minLen), finalEcbCipher2(1:minLen));
    
    ecbKeyMod = ecbKey;
    ecbKeyMod(1) = bitxor(ecbKeyMod(1), uint8(1));
    ecbSecretKeyMod = SecretKeySpec(int8(ecbKeyMod), 'AES');
    ecbCipherObj.init(Cipher.ENCRYPT_MODE, ecbSecretKeyMod);
    ecbCipherBytes3 = typecast(ecbCipherObj.doFinal(int8(message)), 'uint8');
    finalEcbCipher3 = ecbCipherBytes3';
    
    minLenK = min(numel(finalEcbCipher), numel(finalEcbCipher3));
    ecbKae = avalanche_effect(finalEcbCipher(1:minLenK), finalEcbCipher3(1:minLenK));
    
    ecbEnt = shannon_entropy(finalEcbCipher);
    ecbLen = numel(finalEcbCipher) - numel(message);
    
    %% Print Results
    fprintf('\n====================================== BENCHMARK COMPARISON RESULTS ======================================\n');
    fprintf('%-25s | %-16s | %-16s | %-16s | %-16s\n', 'Metric', 'Quantum-ARX', 'AES-CBC (256)', '3DES-CBC', 'AES-ECB (128)');
    fprintf('----------------------------------------------------------------------------------------------------------\n');
    fprintf('%-25s | %-16.5f | %-16.5f | %-16.5f | %-16.5f\n', 'Encryption Time (s)', arxEncTime, aesEncTime, desEncTime, ecbEncTime);
    fprintf('%-25s | %-16.5f | %-16.5f | %-16.5f | %-16.5f\n', 'Decryption Time (s)', arxDecTime, aesDecTime, desDecTime, ecbDecTime);
    fprintf('%-25s | %-16d | %-16d | %-16d | %-16d\n', 'Total Length Change (B)', arxLen, aesLen, desLen, ecbLen);
    fprintf('%-25s | %-16.4f | %-16.4f | %-16.4f | %-16.4f\n', 'Shannon Entropy', arxEnt, aesEnt, desEnt, ecbEnt);
    fprintf('%-25s | %-16.2f | %-16.2f | %-16.2f | %-16.2f\n', 'Plain Avalanche (%)', arxAe, aesAe, desAe, ecbAe);
    fprintf('%-25s | %-16.2f | %-16.2f | %-16.2f | %-16.2f\n', 'Key Avalanche (%)', arxKae, aesKae, desKae, ecbKae);
    fprintf('==========================================================================================================\n');
end

% Re-include localized test functions 
function H = shannon_entropy(data)
    data   = double(data(:));
    counts = histcounts(data, 0:256); 
    counts = counts(counts > 0);
    n      = sum(counts);
    p      = counts / n;
    H      = -sum(p .* log2(p));
end

function score = avalanche_effect(cipher1, cipher2)
    xorBytes    = bitxor(uint8(cipher1), uint8(cipher2));
    flippedBits = sum(arrayfun(@(b) sum(dec2bin(b,'8')-'0'), xorBytes));
    totalBits   = numel(cipher1) * 8;
    score       = (flippedBits / totalBits) * 100.0;
end

% Localized stubs for qcEncrypt/qcDecrypt so it works identically
% In reality, this script should sit in the same folder as your main crypto logic.
% It simply calls qcEncrypt defined in quantum_crypto.m! Because MATLAB handles this 
% dynamically, simply running this script will bridge the path context.
