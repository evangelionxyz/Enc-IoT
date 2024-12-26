import pandas as pd
import matplotlib.pyplot as plt

data = {
    'Iterations': [100, 500, 1000,2000, 5000, 10000, 20000],
    'AES_Encryption': [0, 2, 5, 8, 18, 38, 81],
    'AES_Decryption': [0, 2, 5, 8, 19, 38, 80],
    'AES_Total': [0.002, 0.006, 0.012, 0.017, 0.038, 0.078, 0.162],
    'RSA_Encryption': [49, 252, 512, 1016, 2515, 5194, 10155],
    'RSA_Decryption': [1817, 9200, 18162, 36529, 91678, 181273, 362707],
    'RSA_Total': [2.317, 9.557, 18.753, 37.678, 94.564, 186.722, 372.954],
    'ECC_Encryption': [0, 3, 7, 13, 33, 66, 128],
    'ECC_Decryption': [0, 3, 6, 12, 30, 58, 126],
    'ECC_Total': [0.005, 0.014, 0.018, 0.029, 0.066, 0.129, 0.259]
}

df = pd.DataFrame(data)

plt.figure(figsize=(12, 8))

plt.plot(df['Iterations'], df['AES_Total'], marker='o', label='AES Total Time')
plt.plot(df['Iterations'], df['RSA_Total'], marker='o', label='RSA Total Time')
plt.plot(df['Iterations'], df['ECC_Total'], marker='o', label='ECC Total Time')

plt.xscale('log')
plt.xlabel('Iterations (log scale)', fontsize=14)
plt.ylabel('Time Elapsed (seconds)', fontsize=14)
plt.title('Encryption Benchmark: AES vs RSA vs ECC - 1 KB Lorem Ipsum Text', fontsize=16)
plt.legend(fontsize=12)
plt.grid(True, which="both", linestyle="--", linewidth=0.5)

plt.show()
