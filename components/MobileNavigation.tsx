"use client";
import React, { useState } from "react";
import {
	Sheet,
	SheetContent,
	SheetTitle,
	SheetTrigger,
} from "@/components/ui/sheet";
import Image from "next/image";
import { usePathname } from "next/navigation";
import { Separator } from "./ui/separator";
import { navItems } from "@/constants";
import { cn } from "@/lib/utils";
import Link from "next/link";
import { Button } from "./ui/button";
import FileUploader from "./FileUploader";
import { signOutUser } from "@/lib/actions/user.actions";

interface Props {
	$id: string;
	accountId: string;
	fullName: string;
	avatar: string;
	email: string;
}

const MobileNavigation = ({
	$id: ownerId,
	accountId,
	fullName,
	avatar,
	email,
}: Props) => {
	const [open, setOpen] = useState(false);
	const pathname = usePathname();

	return (
		<header className="mobile-header">
			<Image
				className="h-auto"
				src="/assets/icons/logo-full-brand.svg"
				alt="logo"
				width={120}
				height={52}
			/>
			<Sheet open={open} onOpenChange={setOpen}>
				<SheetTrigger>
					<Image
						src="/assets/icons/menu.svg"
						alt="search"
						width={30}
						height={30}
					/>
				</SheetTrigger>
				<SheetContent className="shad-sheet h-screen px-3">
					<SheetTitle>
						<div className="header-user">
							<Image
								src={avatar}
								alt="avatar"
								width={44}
								height={44}
								className="header-user-avatar"
							/>
							<div className="sm:hidden lg:block truncate">
								<p className="subtilte-2 capitalize">{fullName}</p>
								<p className="caption truncate">{email}</p>
							</div>
						</div>
						<Separator className="mb-4 bg-light-200/20" />
					</SheetTitle>
					<nav className="mobile-nav">
						<ul>
							{navItems.map(({ url, name, icon }) => (
								<Link href={url} key={name} className="lg:w-full">
									<li
										className={cn(
											"mobile-nav-item",
											pathname === url && "shad-active",
										)}
									>
										<Image
											src={icon}
											alt={name}
											width={24}
											height={24}
											className={cn(
												"nav-icon",
												pathname === url && "nav-icon-active",
											)}
										/>
										<p>{name}</p>
									</li>
								</Link>
							))}
						</ul>
					</nav>
					<Separator className="my-5 bg-light-200/20" />
					<div className="flex flex-col justify-between gap-5 pb-5">
						<FileUploader accountId={accountId} ownerId={ownerId} />
						<Button
							type="submit"
							className="mobile-sign-out-button"
							onClick={async () => {
								await signOutUser();
							}}
						>
							<Image
								src="/assets/icons/logout.svg"
								alt="logo"
								width={24}
								height={24}
							/>
							<p>Logout</p>
						</Button>
					</div>
				</SheetContent>
			</Sheet>
		</header>
	);
};

export default MobileNavigation;
