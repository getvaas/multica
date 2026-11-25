"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { useQueryClient } from "@tanstack/react-query";
import { sanitizeNextUrl, useAuthStore } from "@multica/core/auth";
import { workspaceKeys } from "@multica/core/workspace/queries";
import { paths, resolvePostAuthDestination } from "@multica/core/paths";
import { api } from "@multica/core/api";
import { createLogger } from "@multica/core/logger";
import type { User } from "@multica/core/types";
import { validateCliCallback, redirectToCliCallback } from "@multica/views/auth";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@multica/ui/components/ui/card";
import { Button } from "@multica/ui/components/ui/button";
import { useT } from "@multica/views/i18n";
import { Loader2 } from "@multica/ui/icons";
import { CliCallbackError } from "@/features/auth/cli-callback-error";
import { callbackErrorFrom, type CallbackError } from "./callback-error";

const authLogger = createLogger("auth.callback");

function CallbackContent() {
  const { t } = useT("auth");
  const router = useRouter();
  const searchParams = useSearchParams();
  const qc = useQueryClient();
  const loginWithGoogle = useAuthStore((s) => s.loginWithGoogle);
  const loginWithOIDC = useAuthStore((s) => s.loginWithOIDC);
  const [error, setError] = useState<CallbackError | null>(null);
  const [desktopToken, setDesktopToken] = useState<string | null>(null);
  // Single-use OAuth codes must only be exchanged once even if React StrictMode
  // re-invokes mount effects in development.
  const exchangedCodeRef = useRef<string | null>(null);

  useEffect(() => {
    const code = searchParams.get("code");
    const errorParam = searchParams.get("error");
    if (errorParam) {
      authLogger.warn("OAuth returned an error parameter", errorParam);
      setError(
        errorParam === "access_denied"
          ? { kind: "access_denied" }
          : { kind: "login_failed" },
      );
      return;
    }

    if (!code) {
      setError({ kind: "missing_code" });
      return;
    }

    if (exchangedCodeRef.current === code) {
      return;
    }
    exchangedCodeRef.current = code;

    const state = searchParams.get("state") || "";
    const redirectUri = `${window.location.origin}/auth/callback`;

    // The login page joins platform, next and the CLI callback with "," and
    // encodes each value. Google carries them in `state`; OIDC keeps its own
    // signed `state` and returns them as `app_state` after the exchange.
    const parseAuthState = (raw: string) => {
      const stateParts = raw.split(",");
      const nextPart = stateParts.find((p) => p.startsWith("next:"));
      let nextRaw: string | null = null;
      if (nextPart) {
        try {
          nextRaw = decodeURIComponent(nextPart.slice(5));
        } catch {
          nextRaw = null;
        }
      }
      const cliCallbackPart = stateParts.find((p) => p.startsWith("cli_callback:"));
      const cliStatePart = stateParts.find((p) => p.startsWith("cli_state:"));
      let cliCallback: string | null = null;
      let cliState = "";
      let invalidCliCallback = false;
      try {
        if (cliCallbackPart !== undefined) {
          cliCallback = decodeURIComponent(cliCallbackPart.slice("cli_callback:".length));
          if (!validateCliCallback(cliCallback)) invalidCliCallback = true;
        }
        if (cliStatePart !== undefined) {
          cliState = decodeURIComponent(cliStatePart.slice("cli_state:".length));
        }
      } catch {
        invalidCliCallback = true;
      }
      return {
        isAppHandoff:
          stateParts.includes("platform:desktop") || stateParts.includes("platform:mobile"),
        // Drop anything that isn't a safe relative path so an attacker-controlled
        // `next:https://evil` cannot redirect here.
        nextUrl: sanitizeNextUrl(nextRaw),
        cliCallback,
        cliState,
        invalidCliCallback,
      };
    };

    const completeWebLogin = async (loggedInUser: User, nextUrl: string | null) => {
      const wsList = await api.listWorkspaces();
      qc.setQueryData(workspaceKeys.list(), wsList);
      const onboarded = loggedInUser.onboarded_at != null;

      // 1. nextUrl wins: a `next=/invite/<id>` always survives the OAuth
      //    round-trip — the user clicked a specific link and we should
      //    honor exactly that destination.
      if (nextUrl) {
        router.push(nextUrl);
        return;
      }

      // 2. Un-onboarded users may have pending invitations on their email even
      //    when no `next=` was carried. Already-onboarded users skip this
      //    lookup — their new invites surface in the sidebar dropdown.
      if (!onboarded) {
        try {
          const invites = await api.listMyInvitations();
          if (invites.length > 0) {
            qc.setQueryData(workspaceKeys.myInvitations(), invites);
            router.push(paths.invitations());
            return;
          }
        } catch {
          // A failed invite lookup is non-fatal: fall through to the normal
          // post-auth destination so the user isn't stuck on this screen.
        }
      }

      // 3. Default: onboarding for first-timers, first workspace for returning
      //    users, /workspaces/new for onboarded users with zero workspaces.
      router.push(resolvePostAuthDestination(wsList, onboarded));
    };

    // OIDC: the server checks its signed state, nonce and PKCE, then hands
    // back the token plus the app_state the login page started with.
    if (state.startsWith("oidc.")) {
      loginWithOIDC(code, state)
        .then(({ user, token, appState }) => {
          const destination = parseAuthState(appState);
          if (destination.invalidCliCallback) {
            setError({ kind: "invalid_cli_callback" });
            return;
          }
          if (destination.cliCallback) {
            redirectToCliCallback(destination.cliCallback, token, destination.cliState);
            return;
          }
          if (destination.isAppHandoff) {
            setDesktopToken(token);
            window.location.href = `multica://auth/callback?token=${encodeURIComponent(token)}`;
            return;
          }
          return completeWebLogin(user, destination.nextUrl);
        })
        .catch((err) => {
          authLogger.error("OIDC callback failed", err);
          setError(callbackErrorFrom(err));
        });
      return;
    }

    const destination = parseAuthState(state);
    if (destination.invalidCliCallback) {
      setError({ kind: "invalid_cli_callback" });
      return;
    }
    const { cliCallback, cliState } = destination;

    if (cliCallback) {
      // CLI login flow: exchange the Google code for a JWT, then redirect the
      // token back to the CLI's local HTTP listener (e.g. WSL2 host).
      api
        .googleLogin(code, redirectUri)
        .then(({ token }) => {
          redirectToCliCallback(cliCallback, token, cliState);
        })
        .catch((err) => {
          authLogger.error("CLI Google OAuth callback failed", err);
          setError(callbackErrorFrom(err));
        });
    } else if (destination.isAppHandoff) {
      // Desktop / mobile flow: exchange code for token, then redirect via deep link
      api
        .googleLogin(code, redirectUri)
        .then(({ token }) => {
          setDesktopToken(token);
          window.location.href = `multica://auth/callback?token=${encodeURIComponent(token)}`;
        })
        .catch((err) => {
          authLogger.error("Desktop Google OAuth callback failed", err);
          setError(callbackErrorFrom(err));
        });
    } else {
      // Normal web flow
      loginWithGoogle(code, redirectUri)
        .then((loggedInUser) => completeWebLogin(loggedInUser, destination.nextUrl))
        .catch((err) => {
          authLogger.error("Web Google OAuth callback failed", err);
          setError(callbackErrorFrom(err));
        });
    }
  }, [searchParams, loginWithGoogle, loginWithOIDC, router, qc]);

  const errorDescription = (() => {
    if (!error) return null;
    switch (error.kind) {
      case "invalid_cli_callback":
        return null;
      case "raw":
        return error.text;
      case "missing_code":
        return t(($) => $.web.callback.missing_code);
      case "access_denied":
        return t(($) => $.web.callback.access_denied);
      case "login_failed":
        return t(($) => $.web.callback.login_failed);
      case "account_disabled":
        return t(($) => $.web.callback.account_disabled);
      case "signup_prohibited":
        return t(($) => $.web.callback.signup_prohibited);
      case "email_not_allowed":
        return t(($) => $.web.callback.email_not_allowed);
      case "google_account_no_email":
        return t(($) => $.web.callback.google_account_no_email);
      case "oauth_code_invalid":
        return t(($) => $.web.callback.oauth_code_invalid);
    }
  })();

  if (desktopToken) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Card className="w-full max-w-sm">
          <CardHeader className="text-center">
            <CardTitle className="text-display-sm">
              {t(($) => $.web.desktop_handoff.opening_title)}
            </CardTitle>
            <CardDescription>
              {t(($) => $.web.desktop_handoff.opening_description)}
            </CardDescription>
          </CardHeader>
          <CardContent className="flex justify-center">
            <Button
              variant="outline"
              onClick={() => {
                window.location.href = `multica://auth/callback?token=${encodeURIComponent(desktopToken)}`;
              }}
            >
              {t(($) => $.web.desktop_handoff.open_button)}
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (error?.kind === "invalid_cli_callback") return <CliCallbackError />;

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Card className="w-full max-w-sm">
          <CardHeader className="text-center">
            <CardTitle className="text-display-sm">
              {t(($) => $.web.callback.failed_title)}
            </CardTitle>
            <CardDescription>
              {errorDescription}
            </CardDescription>
          </CardHeader>
          <CardContent className="flex justify-center">
            <a href={paths.login()} className="text-primary underline-offset-4 hover:underline">
              {t(($) => $.web.callback.back_to_login)}
            </a>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center">
      <Card className="w-full max-w-sm">
        <CardHeader className="text-center">
          <CardTitle className="text-display-sm">
            {t(($) => $.web.callback.signing_in)}
          </CardTitle>
        </CardHeader>
        <CardContent className="flex justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    </div>
  );
}

export default function CallbackPage() {
  return (
    <Suspense fallback={null}>
      <CallbackContent />
    </Suspense>
  );
}
