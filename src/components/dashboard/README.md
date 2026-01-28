# Dashboard Components Documentation

This directory contains all the components for the QuantumIQ Dashboard page. Each component represents a specific information domain as required by the specification.

## Components Structure

### 1. AccountIdentity.tsx
Handles the "Account & Identity" section of the dashboard, displaying:
- Account status and access level
- Security settings (2FA, email verification)
- Login history and session information
- Proper loading, error, and empty states

### 2. PortfolioOverview.tsx
Manages the "Portfolio Overview" section, showing:
- High-level portfolio metrics
- Asset allocation breakdown
- Geographic and currency exposure
- Top holdings preview
- Diversity score and position counts

### 3. RiskExposure.tsx
Handles the "Risk & Exposure Awareness" section, featuring:
- Overall risk score visualization
- Risk category breakdowns (market, volatility, concentration, etc.)
- Compliance status indicators
- Margin usage and leverage ratios

### 4. ModelStatus.tsx
Manages the "AI / Model Interaction Status" section, including:
- Active model statuses
- Model readiness states
- Analysis queue status
- API usage statistics
- Important disclaimers about model outputs

### 5. SystemNotices.tsx
Handles the "System & Security Notices" section, with:
- Security alerts and warnings
- Policy and maintenance notifications
- Priority-based categorization
- Dismissal and read/unread functionality

## Design Principles

### Visual Style
- Dark theme with black/near-black backgrounds
- White/gray typography for readability
- Consistent spacing using 8px base units
- Minimal borders and subtle shadows
- Responsive grid layout

### Security Considerations
- No sensitive data logging
- No raw token exposure
- No full IP address disclosure
- Sanitized data display
- Proper authentication checks

### User Experience
- Skeleton loaders during data fetching
- Clear error messaging
- Empty state handling
- Accessible ARIA labels
- Keyboard navigation support

## Integration Points

Components expect data matching the interfaces defined in `src/types/dashboard.ts`:
- `UserAccountData`
- `PortfolioSummary` 
- `RiskAssessment`
- `ModelStatus`
- `SystemNotice`

Each component manages its own loading state and follows the pattern:
```typescript
interface ComponentProps {
  data: DataType | null;
  status: 'loading' | 'loaded' | 'error' | 'empty';
}
```

## Adding New Sections

To add a new dashboard section:
1. Define the data interface in `src/types/dashboard.ts`
2. Create a new component in this directory
3. Add the component import to `src/app/(app)/dashboard/page.tsx`
4. Include the component in the main grid layout
5. Update the loading state management accordingly

## Testing Considerations

Components are designed to be testable:
- Pure UI rendering logic
- Prop-driven behavior
- Isolated state management
- Mock-friendly data interfaces

## Future Extensibility

This architecture supports:
- Individual section loading states
- Independent data fetching
- Type-safe data contracts
- Clean separation of concerns
- Scalable component composition