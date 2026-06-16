import { BlogFeed } from "@/components/landing/BlogFeed";
import { Dashboard } from "@/components/landing/Dashboard";
import { Footer } from "@/components/landing/Footer";
import { Header } from "@/components/landing/Header";
import { Hero } from "@/components/landing/Hero";
import {
  AiExpert,
  Features,
  GetStarted,
  HowItWorks,
  ProblemFix,
  WhatItChecks,
  WhyAvai,
} from "@/components/landing/sections";

export const dynamic = "force-dynamic";

export default function Home() {
  return (
    <>
      <Header />
      <main>
        <Hero />
        <ProblemFix />
        <HowItWorks />
        <WhatItChecks />
        <Features />
        <WhyAvai />
        <AiExpert />
        <Dashboard />
        <GetStarted />
        <BlogFeed />
      </main>
      <Footer />
    </>
  );
}
