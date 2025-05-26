import ComponentCard from "@/components/common/ComponentCard";
import PageBreadcrumb from "@/components/common/PageBreadCrumb";
import MonitoredUsersTable from "@/components/tables/MonitoredUsersTable";
import { Metadata } from "next";
import React from "react";

export const metadata: Metadata = {
  title: "Utilizatori",
};

export default function MonitoredUsers() {
  return (
    <div>
      <PageBreadcrumb pageTitle="Utilizatori" />
      <div className="space-y-6">
        <ComponentCard title="">
          <MonitoredUsersTable />
        </ComponentCard>
      </div>
    </div>
  );
}
