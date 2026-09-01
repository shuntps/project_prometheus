/*
  Every word the landing page shows lives here. The public name is not among
  them: it is configuration, injected where it is displayed.
*/
export const landingContent = {
  navigation: [
    { label: "Platform", href: "#platform" },
    { label: "Discovery", href: "#discovery" },
    { label: "Creators", href: "#creators" },
  ],
  hero: {
    eyebrow: "In development",
    heading: "A place for creators and the communities around them.",
    body: "Creators broadcast to a room of their own. Their audience finds them, follows them and takes part while the room is live.",
    primaryAction: { label: "Create an account", href: "/register" },
    primaryActionNote:
      "An account can be created now. None of what is described here is available to it yet.",
    secondaryAction: { label: "What the platform does", href: "#platform" },
  },
  sections: [
    {
      id: "platform",
      heading: "Live rooms",
      body: "A creator opens a room and broadcasts to it. The people watching can react, take part and stay for as long as the room is open.",
      points: [
        "One room per creator, opened and closed by the creator.",
        "An audience that takes part while the room is live.",
        "A private mode a creator can move a conversation into.",
      ],
    },
    {
      id: "discovery",
      heading: "Discovery",
      body: "The platform has a surface where rooms currently open can be found, and a way to return to the creators someone already follows.",
      points: [
        "Rooms that are open right now.",
        "The creators an account already follows.",
        "Browsing that works the same on a phone and on a desktop.",
      ],
    },
    {
      id: "creators",
      heading: "Creator tools",
      body: "A creator account has its own surface for setting up a room, seeing what happened in it and managing the account itself.",
      points: [
        "Room setup and broadcast controls.",
        "A record of what happened in past sessions.",
        "Account and access settings in one place.",
      ],
    },
  ],
  closing: {
    heading: "The features described here are not available yet.",
    body: "This page describes what is being built. An account can be created and its address confirmed; nothing above is open to it.",
  },
  footer: {
    note: "This page is part of a platform under development.",
  },
} as const;
