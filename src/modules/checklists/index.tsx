import { Navigate, Route, Routes } from 'react-router-dom'
import './checklists.css'
import { ChecklistsHome } from './ChecklistsHome'
import { ReviewPage } from './ReviewPage'
import { useReviews } from './useReviews'

export default function ChecklistsModule() {
  const store = useReviews()
  return (
    <Routes>
      <Route index element={<ChecklistsHome store={store} />} />
      <Route path="review/:id" element={<ReviewPage store={store} />} />
      {/* Redirect instead of rendering the home page here: relative links inside a splat route would
          resolve against the unknown path (e.g. /checklists/x/review/123) and never match. */}
      <Route path="*" element={<Navigate to=".." relative="route" replace />} />
    </Routes>
  )
}
