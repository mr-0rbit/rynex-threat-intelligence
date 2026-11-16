import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { Footer } from "../components/Footer";

describe("Footer", () => {
  it("renders the brand name", () => {
    render(<Footer />);
    expect(screen.getAllByText(/Rynex/i).length).toBeGreaterThan(0);
  });

  it("renders the newsletter input", () => {
    render(<Footer />);
    expect(
      screen.getByPlaceholderText("security@enterprise.com"),
    ).toBeInTheDocument();
  });

  it("shows a thank-you state after a valid subscription", async () => {
    render(<Footer />);
    const input = screen.getByPlaceholderText("security@enterprise.com");
    fireEvent.change(input, { target: { value: "analyst@enterprise.com" } });
    const submit = screen.getByRole("button", { name: /subscribe/i });
    fireEvent.click(submit);
    expect(await screen.findByText(/thank you/i)).toBeInTheDocument();
  });

  it("does not subscribe with an invalid email", () => {
    render(<Footer />);
    const input = screen.getByPlaceholderText("security@enterprise.com");
    fireEvent.change(input, { target: { value: "not-an-email" } });
    fireEvent.click(screen.getByRole("button", { name: /subscribe/i }));
    expect(screen.queryByText(/thank you/i)).not.toBeInTheDocument();
  });
});