import pandas as pd
import matplotlib.pyplot as plt

data = {
    'Iterations': [100, 500, 1000],
    'AES_Total': [0.001, 0.006, 0.011],
    'RSA_Total': [3.396, 13.195, 26.528],
    'ECC_Total': [0.006, 0.011, 0.018]
}

df = pd.DataFrame(data)

plt.figure(figsize=(12, 8))

plt.plot(df['Iterations'], df['AES_Total'], marker='o', label='AES Total Time')
plt.plot(df['Iterations'], df['RSA_Total'], marker='o', label='RSA Total Time')
plt.plot(df['Iterations'], df['ECC_Total'], marker='o', label='ECC Total Time')

plt.xscale('log')
plt.xlabel('Function Calls (log scale)', fontsize=14)
plt.ylabel('Time Elapsed (seconds)', fontsize=14)
plt.title('Encryption Recursive Benchmark: AES vs RSA vs ECC - 1 KB Lorem Ipsum Text', fontsize=16)
plt.legend(fontsize=12)
plt.grid(True, which="both", linestyle="--", linewidth=0.5)

plt.show()
