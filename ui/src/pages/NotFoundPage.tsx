import { Link } from "react-router-dom";
import { EmptyState } from "../components/Primitives";

export function NotFoundPage() {
  return (
    <EmptyState
      title="Workbench route not found"
      detail="The requested record or workspace route does not exist."
      headingLevel={1}
      action={<Link className="primary-button" to="/">Return to overview</Link>}
    />
  );
}
