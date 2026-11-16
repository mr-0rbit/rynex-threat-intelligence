import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import {
  SeverityBadge,
  Badge,
  StatusBadge,
  StatCard,
  EmptyState,
  Spinner,
  timeAgo,
} from "../components/ui";

describe("timeAgo", () => {
  it("returns '—' for null/undefined", () => {
    expect(timeAgo(null)).toBe("—");
    expect(timeAgo(undefined)).toBe("—");
  });

  it("returns 'just now' for sub-minute differences", () => {
    const now = new Date().toISOString();
    expect(timeAgo(now)).toBe("just now");
  });

  it("formats minutes", () => {
    const then = new Date(Date.now() - 5 * 60_000).toISOString();
    expect(timeAgo(then)).toBe("5m ago");
  });

  it("formats hours", () => {
    const then = new Date(Date.now() - 3 * 3600_000).toISOString();
    expect(timeAgo(then)).toBe("3h ago");
  });

  it("formats days", () => {
    const then = new Date(Date.now() - 2 * 86_400_000).toISOString();
    expect(timeAgo(then)).toBe("2d ago");
  });
});

describe("SeverityBadge", () => {
  it("renders CRITICAL for critical severity", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
  });

  it("falls back to INFO for unknown severity", () => {
    render(<SeverityBadge severity="totally-bogus" />);
    expect(screen.getByText("INFO")).toBeInTheDocument();
  });

  it("is case-insensitive", () => {
    render(<SeverityBadge severity="HIGH" />);
    expect(screen.getByText("HIGH")).toBeInTheDocument();
  });
});

describe("StatusBadge", () => {
  it("renders a known status label", () => {
    render(<StatusBadge status="acknowledged" />);
    expect(screen.getByText("acknowledged")).toBeInTheDocument();
  });

  it("falls back to unknown for bogus status", () => {
    render(<StatusBadge status="nope" />);
    expect(screen.getByText("nope")).toBeInTheDocument();
  });

  it("normalizes underscores to spaces", () => {
    render(<StatusBadge status="false_positive" />);
    expect(screen.getByText("false positive")).toBeInTheDocument();
  });
});

describe("Badge", () => {
  it("renders children", () => {
    render(<Badge variant="cyan">RTIP</Badge>);
    expect(screen.getByText("RTIP")).toBeInTheDocument();
  });

  it("falls back to neutral variant", () => {
    render(<Badge variant={"bogus" as never}>X</Badge>);
    expect(screen.getByText("X")).toBeInTheDocument();
  });
});

describe("StatCard", () => {
  it("renders label, value and hint", () => {
    render(<StatCard label="Alerts" value={42} hint="live" />);
    expect(screen.getByText("Alerts")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("live")).toBeInTheDocument();
  });

  it("formats numbers with commas", () => {
    render(<StatCard label="x" value={1234} />);
    expect(screen.getByText("1,234")).toBeInTheDocument();
  });

  it("renders a string value untouched", () => {
    render(<StatCard label="x" value="n/a" />);
    expect(screen.getByText("n/a")).toBeInTheDocument();
  });
});

describe("EmptyState", () => {
  it("renders the message", () => {
    render(<EmptyState message="No intel yet" />);
    expect(screen.getByText("No intel yet")).toBeInTheDocument();
  });
});

describe("Spinner", () => {
  it("renders the default label", () => {
    render(<Spinner />);
    expect(screen.getByText("Loading intelligence…")).toBeInTheDocument();
  });

  it("renders a custom label", () => {
    render(<Spinner label="Authenticating…" />);
    expect(screen.getByText("Authenticating…")).toBeInTheDocument();
  });
});