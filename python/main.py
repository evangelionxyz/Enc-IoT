import pandas as pd
import matplotlib.pyplot as plt

data = {
    'Iterations': [100, 1000, 10000],
    'AES_Encryption': [0, 5, 55],
    'AES_Decryption': [0, 5, 53],
    'AES_Total': [0.002, 0.011, 0.111],
    'RSA_Encryption': [77, 735, 7636],
    'RSA_Decryption': [2575, 26156, 267090],
    'RSA_Total': [2.861, 27.204, 275.277],
    'ECC_Encryption': [0, 9, 71],
    'ECC_Decryption': [0, 6, 57],
    'ECC_Total': [0.02, 0.023, 0.132]
}

# Convert to DataFrame
df = pd.DataFrame(data)

# Plotting
plt.figure(figsize=(12, 8))

# Plot for each method
plt.plot(df['Iterations'], df['AES_Total'], marker='o', label='AES Total Time')
plt.plot(df['Iterations'], df['RSA_Total'], marker='o', label='RSA Total Time')
plt.plot(df['Iterations'], df['ECC_Total'], marker='o', label='ECC Total Time')

# Customizing the plot
plt.xscale('log')  # Log scale for x-axis
plt.xlabel('Iterations (log scale)', fontsize=14)
plt.ylabel('Time Elapsed (seconds)', fontsize=14)
plt.title('Encryption Benchmark: AES vs RSA vs ECC - 1 KB Lorem Ipsum Text', fontsize=16)
plt.legend(fontsize=12)
plt.grid(True, which="both", linestyle="--", linewidth=0.5)

plt.savefig('encryption_benchmark.jpg', format='jpg', dpi=300)

# Show plot
plt.show()


