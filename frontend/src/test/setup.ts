import '@testing-library/jest-dom/vitest';

// jsdom has no layout engine, so it implements no scrolling APIs at all. Components
// that scroll a found line into view would throw here for a reason that says nothing
// about the component. A no-op keeps that out of the way; where scrolling behaviour
// matters it is asserted through the target class, not through the scroll itself.
if (!Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = () => {};
}
