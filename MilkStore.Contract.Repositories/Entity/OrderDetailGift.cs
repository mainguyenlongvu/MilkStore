using MilkStore.Core.Base;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace MilkStore.Contract.Repositories.Entity
{
    public class OrderDetailGift : BaseEntity
    {
        public string? OrderGiftId { get; set; }

        public string? GiftId { get; set; }

        public int quantity { get; set; }

        public virtual OrderGift orderGift { get; set; }
        public virtual Gift Gift { get; set; }
    }
}
