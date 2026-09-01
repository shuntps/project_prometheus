/*
  Every word these surfaces show. Nothing here names an address, states that an
  account exists, or says that a message was sent or will arrive.
*/
export const registrationContent = {
  register: {
    title: "Create an account",
    intro:
      "An account is created for the address given here, and stays unusable until that address is confirmed.",
    email: "Email address",
    password: "Password",
    passwordHint: "Use a long password you use nowhere else. The service decides what it accepts.",
    confirmation: "Repeat the password",
    confirmationHint: "Checked here, and never sent.",
    submit: "Create the account",
    submitting: "Sending…",
    signInPrompt: "Already have an account?",
    signIn: "Sign in",
    errors: {
      mismatch: "The two passwords are not identical.",
      invalid: "The submitted values were not accepted.",
      tooLarge: "The submitted values are too large.",
      limited: "Too many attempts. Wait a moment and try again.",
      blocked: "This request was refused. Reload the page and try again.",
      unavailable: "The service is unavailable. Try again shortly.",
    },
    accepted: {
      heading: "Check that mailbox",
      body: "Look there for a confirmation message. This page answers the same way for every address, so it says nothing about the account and nothing about what was sent.",
    },
  },
  resend: {
    heading: "Ask for another message",
    body: "Give the address again. The answer is the same for every address.",
    email: "Email address",
    submit: "Ask for a message",
    submitting: "Sending…",
    errors: {
      invalid: "The submitted value was not accepted.",
      tooLarge: "The submitted value is too large.",
      limited: "Too many attempts. Wait a moment and try again.",
      blocked: "This request was refused. Reload the page and try again.",
      unavailable: "The service is unavailable. Try again shortly.",
    },
    accepted: {
      heading: "Check that mailbox",
      body: "Look there for a confirmation message. This page answers the same way for every address, so it says nothing about the account and nothing about what was sent.",
    },
  },
  verify: {
    title: "Confirm the address",
    checking: "Confirming the address…",
    /* One 204 answers a first consumption and a coherent second presentation
       alike, and says nothing about what the account may do now. */
    verified: {
      heading: "The address is confirmed",
      body: "No session was opened for you. Signing in is a separate step, and this page cannot say how it will go.",
      signIn: "Sign in",
    },
    /* A page opened without a link is not a link that failed. Saying so is
       about this window's own address bar and discloses nothing about any
       account. */
    absent: {
      heading: "No confirmation link here",
      body: "This page was opened without a confirmation link. You can ask for another message below.",
    },
    refused: {
      heading: "This link cannot be used",
      body: "Nothing here says why. Another message can be asked for below.",
    },
    register: "Create an account",
    limited: {
      heading: "Too many attempts",
      body: "Wait a moment, then try again.",
    },
    unavailable: {
      heading: "The service is unavailable",
      body: "The address was not confirmed. Try again shortly.",
    },
    retry: "Try again",
  },
} as const;
