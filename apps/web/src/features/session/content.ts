/* Every word this surface shows. No identifier of an account appears here. */
export const sessionContent = {
  header: {
    loading: "Checking your session",
    signIn: "Sign in",
    signedIn: "Signed in",
    signOut: "Sign out",
    limited: "Too many requests",
    unavailable: "Session unavailable",
    retry: "Try again",
  },
  signIn: {
    title: "Sign in",
    intro: "Use the address and password of an existing account.",
    email: "Email address",
    password: "Password",
    submit: "Sign in",
    submitting: "Signing in…",
    errors: {
      invalid: "Check the address and the password, then try again.",
      rejected: "The credentials were not accepted.",
      tooLarge: "The submitted values are too large.",
      limited: "Too many attempts. Wait a moment and try again.",
      blocked: "This request was refused. Reload the page and try again.",
      unavailable: "The service is unavailable. Try again shortly.",
    },
  },
} as const;
