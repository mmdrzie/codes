// src/types/global.d.ts

interface EthereumProvider {
  isMetaMask?: boolean;
  isCoinbaseWallet?: boolean;
  providers?: EthereumProvider[]; // برای والت‌های چندگانه مثل Rainbow

  request: (request: { method: string; params?: Array<any> | Record<string, any> }) => Promise<any>;
  on: (event: string, callback: (...args: any[]) => void) => void;
  removeListener: (event: string, callback: (...args: any[]) => void) => void;
}

declare global {
  interface Window {
    ethereum?: EthereumProvider;
  }
}

// این خط برای جلوگیری از خطای "Augmentations for the global scope can only be directly nested..." مهمه
export {};