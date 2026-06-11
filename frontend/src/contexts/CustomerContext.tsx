import { createContext, useContext, useState } from 'react'

export interface ActiveCustomer {
  id: string
  name: string
}

interface CustomerContextType {
  activeCustomer: ActiveCustomer | null
  setActiveCustomer: (c: ActiveCustomer | null) => void
}

const CustomerContext = createContext<CustomerContextType>({
  activeCustomer: null,
  setActiveCustomer: () => {},
})

export function CustomerProvider({ children }: { children: React.ReactNode }) {
  const [activeCustomer, setActiveCustomerState] = useState<ActiveCustomer | null>(() => {
    try {
      return JSON.parse(localStorage.getItem('activeCustomer') || 'null')
    } catch {
      return null
    }
  })

  const setActiveCustomer = (c: ActiveCustomer | null) => {
    setActiveCustomerState(c)
    if (c) localStorage.setItem('activeCustomer', JSON.stringify(c))
    else localStorage.removeItem('activeCustomer')
  }

  return (
    <CustomerContext.Provider value={{ activeCustomer, setActiveCustomer }}>
      {children}
    </CustomerContext.Provider>
  )
}

export const useCustomer = () => useContext(CustomerContext)
