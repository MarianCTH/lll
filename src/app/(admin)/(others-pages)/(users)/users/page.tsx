import ComponentCard from "@/components/common/ComponentCard";
import PageBreadcrumb from "@/components/common/PageBreadCrumb";
import UsersTable from "@/components/tables/usersTable";
import { Metadata } from "next";
import React from "react";

export const metadata: Metadata = {
  title: "Utilizatori",
};

export default function BasicTables() {
  return (
    <div>
      <PageBreadcrumb pageTitle="Utilizatori" />
      <div className="space-y-6">
        <ComponentCard title="">
          <UsersTable />
        </ComponentCard>
      </div>
    </div>
  );
}
