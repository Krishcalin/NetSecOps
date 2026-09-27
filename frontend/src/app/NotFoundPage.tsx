import { NavLink } from 'react-router-dom';
import { PageHeader } from '../components/PageHeader';

export function NotFoundPage() {
  return (
    <div className="page">
      <PageHeader
        icon="alert"
        title="Page not found"
        subtitle="This area may belong to a later phase, or the link may be out of date."
      />
      <NavLink className="button button--primary" to="/">
        Back to dashboard
      </NavLink>
    </div>
  );
}
