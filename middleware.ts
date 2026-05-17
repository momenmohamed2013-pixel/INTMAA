import { NextResponse, NextRequest } from "next/server";
import { verifyToken } from "@/lib/auth";

const PUBLIC_PATHS = ["/login", "/api/auth/login"];

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // Allow public paths
  if (PUBLIC_PATHS.some((p) => pathname.startsWith(p))) {
    return NextResponse.next();
  }

  // Allow static files
  if (pathname.startsWith("/_next") || pathname.startsWith("/favicon")) {
    return NextResponse.next();
  }

  const token = req.cookies.get("auth-token")?.value;

  if (!token) {
    return NextResponse.redirect(new URL("/login", req.url));
  }

  const session = await verifyToken(token);

  if (!session) {
    const res = NextResponse.redirect(new URL("/login", req.url));
    res.cookies.set("auth-token", "", { maxAge: 0, path: "/" });
    return res;
  }

  // Role-based route protection
  if (pathname.startsWith("/admin") && session.role !== "ADMIN") {
    return NextResponse.redirect(new URL("/engineer", req.url));
  }

  if (pathname.startsWith("/engineer") && session.role !== "ENGINEER") {
    return NextResponse.redirect(new URL("/admin", req.url));
  }

  // Redirect root to correct dashboard
  if (pathname === "/") {
    return NextResponse.redirect(new URL(session.role === "ADMIN" ? "/admin" : "/engineer", req.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
