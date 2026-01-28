'use client';

import * as React from 'react';

import { cn } from '@/lib/utils';

// Simplified select component using native HTML select
const Select = ({ children, onValueChange, value, ...props }: any) => {
  return (
    <select
      className="flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
      onChange={(e) => onValueChange?.(e.target.value)}
      value={value}
      {...props}
    >
      {children}
    </select>
  );
};

const SelectTrigger = ({ children, className, ...props }: any) => {
  return (
    <div 
      className={cn(
        'flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50',
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
};

const SelectContent = ({ children, className, ...props }: any) => {
  return (
    <div 
      className={cn(
        'relative z-50 max-h-60 min-w-[8rem] overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-md',
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
};

const SelectItem = ({ children, value, className, ...props }: any) => {
  return (
    <option 
      value={value}
      className={cn('relative w-full cursor-default select-none py-1.5 pl-8 pr-2 text-sm outline-none focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50', className)}
      {...props}
    >
      {children}
    </option>
  );
};

export {
  Select,
  SelectTrigger,
  SelectContent,
  SelectItem,
};