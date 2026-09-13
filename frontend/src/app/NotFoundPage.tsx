import { NavLink } from 'react-router-dom';

export function NotFoundPage() {
  return (
    <div className="page">
      <header className="page__header">
        <h1>Page not found</h1>
        <p className="page__subtitle">
          This area may belong to a later phase, or the link may be out of date.
        </p>
      </header>
      <NavLink className="button button--primary" to="/">
        Back to dashboard
      </NavLink>
    </div>
  );
}
