import { Component, ElementRef, Input, OnInit, ViewChild } from "@angular/core";
import { CStructRepr, MemoryChange } from "src/generated/traceapp_pb";

export class VarTableComponentOptions {
  scrollToBottom: boolean = true;
}

@Component({
  selector: "app-var-table",
  templateUrl: "./var-table.component.html",
  styleUrls: ["./var-table.component.css"]
})
export class VarTableComponent implements OnInit {
  selectedVarName = "GPIOB_PDOR";
  mode = 0;
  ngOnInit(): void {
    this.autoScroll();
  }

  @Input() data: MemoryChange[] = [];
  @Input() watchList: MemoryChange[] = [];
  @Input() options: VarTableComponentOptions = new VarTableComponentOptions();
  @ViewChild("eventsTable") eventsTable?: ElementRef = undefined;

  getChangeRep(item: MemoryChange): string {
    // <td>{{ item.getSymbolName() + "." + item.getMemberVar()?.getName() }}</td>

    if (item.hasBasicRepr()) {
      return (
        "Basic " + item.getSymbolName() + "." + item.getMemberVar()?.getName()
      );
    } else if (item.hasArrayRepr()) {
      return (
        "Array " + item.getSymbolName() + "." + item.getMemberVar()?.getName()
      );
    } else {
      return (
        "Struct " + item.getSymbolName() + "." + item.getMemberVar()?.getName()
      );
    }
  }

  public get latestItem(): CStructRepr | undefined {
    // const csr = new CStructRepr();

    if (this.watchList.length > 0) {
      return this.watchList[this.watchList.length - 1].getStructRepr();
    } else {
      return undefined;
    }
  }

  autoScroll() {
    if (this.options.scrollToBottom) {
      this.eventsTable?.nativeElement.scrollIntoView({
        behavior: "instant",
        block: "end"
      });
    }

    setTimeout(() => {
      this.autoScroll();
    }, 100);
  }
}
